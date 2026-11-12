"""业务服务层：账号、重置令牌、会话、演示邮箱。

事务边界约定
============
1. Argon2 哈希 / 校验（可能耗时数秒）一律在写事务 **之外** 执行；
2. 需要原子性的状态迁移全部放进单个 ``BEGIN IMMEDIATE`` 事务；
3. 失败路径不开启或回滚事务，保证“重置失败不改密码或链接状态”。
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from . import security
from .config import settings
from .db import get_mail_conn, write_tx

HASH_DELAY_KEY = "hash_delay_ms"


class ResetRaceError(Exception):
    """链接在最终提交时已失效（被消费 / 被新链接作废旧 / 过期）。"""


class LoginRaceError(Exception):
    """密码校验通过后的复查发现密码已被重置。"""


# --------------------------------------------------------------------------
# 应用设置（哈希延迟可运行时调整）
# --------------------------------------------------------------------------

def get_hash_delay_seconds(conn: sqlite3.Connection) -> float:
    row = conn.execute(
        "SELECT value FROM app_settings WHERE key = ?", (HASH_DELAY_KEY,)
    ).fetchone()
    if row is None:
        return settings.default_hash_delay_ms / 1000.0
    return int(row["value"]) / 1000.0


def set_hash_delay_ms(conn: sqlite3.Connection, delay_ms: int) -> None:
    delay_ms = max(0, min(delay_ms, 60_000))
    with write_tx(conn):
        conn.execute(
            "INSERT INTO app_settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (HASH_DELAY_KEY, str(delay_ms)),
        )


# --------------------------------------------------------------------------
# 预置账号
# --------------------------------------------------------------------------

def seed_users(conn: sqlite3.Connection) -> list[str]:
    """幂等预置两个演示账号，返回本次新建的用户名。"""
    # 先做短读检查是否已初始化
    if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
        return []

    # 哈希在任何写事务之外计算（即便此时没有请求，也遵守统一约定）
    delay = get_hash_delay_seconds(conn)
    now = int(time.time())
    prepared = [
        (username, email, security.hash_password(password, delay), now)
        for username, email, password in settings.seed_users
    ]

    seeded: list[str] = []
    with write_tx(conn):
        # 事务内复查，避免与并发的初始化竞争导致重复插入
        if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
            return []
        for username, email, pw_hash, created_at in prepared:
            conn.execute(
                "INSERT INTO users(username, email, password_hash, created_at) "
                "VALUES(?, ?, ?, ?)",
                (username, email, pw_hash, created_at),
            )
            seeded.append(username)
    return seeded


# --------------------------------------------------------------------------
# 用户查询
# --------------------------------------------------------------------------

def find_user_by_login(conn: sqlite3.Connection, login: str) -> sqlite3.Row | None:
    """登录名支持用户名或邮箱。"""
    return conn.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?", (login, login)
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# --------------------------------------------------------------------------
# 重置链接：申请 / 状态核验 / 消费
# --------------------------------------------------------------------------

@dataclass
class ResetRequestResult:
    email: str
    token: str           # 原始令牌，仅这一次通过邮件返回
    expires_at: int


def request_password_reset(
    conn: sqlite3.Connection, login: str
) -> ResetRequestResult | None:
    """申请重置链接。

    同一账号签发新链接时，在同一写事务里把该账号所有未消费的旧链接
    标记为 superseded —— 旧链接即便仍在有效期内也立刻失效，
    正在途中的旧链接重置提交会在最终核验时失败。

    邮件由路由层在事务提交后投递（需要请求的 base url 拼接链接）。
    """
    user = find_user_by_login(conn, login)
    if user is None:
        # 不暴露账号是否存在；邮箱也不会发信
        return None

    now = int(time.time())
    token = security.generate_token()
    digest = security.digest_token(token)
    expires_at = now + settings.reset_ttl_seconds

    with write_tx(conn):
        conn.execute(
            "UPDATE reset_tokens SET superseded_at = ? "
            "WHERE user_id = ? AND consumed_at IS NULL AND superseded_at IS NULL",
            (now, user["id"]),
        )
        conn.execute(
            "INSERT INTO reset_tokens"
            "(user_id, token_digest, expires_at, created_at) "
            "VALUES(?, ?, ?, ?)",
            (user["id"], digest, expires_at, now),
        )

    return ResetRequestResult(email=user["email"], token=token, expires_at=expires_at)


def token_failure_reason(
    conn: sqlite3.Connection, token_digest: str, now: int | None = None
) -> str | None:
    """返回链接不可用的原因；None 表示当前有效。

    只读检查，绝不修改任何状态——重置失败时链接状态保持不变。
    """
    now = int(time.time()) if now is None else now
    row = conn.execute(
        "SELECT * FROM reset_tokens WHERE token_digest = ?", (token_digest,)
    ).fetchone()
    if row is None:
        return "unknown"
    if row["consumed_at"] is not None:
        return "consumed"
    if row["superseded_at"] is not None:
        return "superseded"
    if row["expires_at"] <= now:
        return "expired"
    return None


def get_active_token(
    conn: sqlite3.Connection, token_digest: str
) -> sqlite3.Row | None:
    if token_failure_reason(conn, token_digest) is not None:
        return None
    return conn.execute(
        "SELECT * FROM reset_tokens WHERE token_digest = ?", (token_digest,)
    ).fetchone()


def prepare_password_reset(
    conn: sqlite3.Connection, token: str, new_password: str
) -> tuple[sqlite3.Row, str]:
    """重置的“慢”阶段：核验链接并计算新哈希，不持任何写锁。

    返回 (令牌行, 新哈希)。链接无效时抛出 ResetRaceError，
    密码问题由调用方在更早的表单校验阶段拦截。
    """
    digest = security.digest_token(token)
    token_row = get_active_token(conn, digest)
    if token_row is None:
        raise ResetRaceError(token_failure_reason(conn, digest) or "unknown")
    delay = get_hash_delay_seconds(conn)
    # 耗时计算在事务外：期间其他进程仍可申请链接、登录、查询身份
    new_hash = security.hash_password(new_password, delay)
    return token_row, new_hash


def commit_password_reset(
    conn: sqlite3.Connection, token: str, new_hash: str
) -> int:
    """重置的“快”阶段：单事务原子完成三件事。

    1. 条件消费链接（仅当仍有效）；
    2. 替换密码哈希并递增 password_version；
    3. 撤销该账号全部会话。

    任一步不满足整体回滚。返回被重置的 user_id；链接已失效则抛
    ResetRaceError 且不做任何修改。跨进程并发时条件 UPDATE 保证
    同一个链接只能成功一次。
    """
    digest = security.digest_token(token)
    now = int(time.time())
    with write_tx(conn):
        cur = conn.execute(
            "UPDATE reset_tokens SET consumed_at = ? "
            "WHERE token_digest = ? AND consumed_at IS NULL "
            "AND superseded_at IS NULL AND expires_at > ?",
            (now, digest, now),
        )
        if cur.rowcount != 1:
            # 显式回滚后抛出；调用方据此提示失败，密码与链接状态均未变
            raise ResetRaceError(
                token_failure_reason(conn, digest, now) or "unknown"
            )
        row = conn.execute(
            "SELECT user_id FROM reset_tokens WHERE token_digest = ?", (digest,)
        ).fetchone()
        user_id = row["user_id"]
        conn.execute(
            "UPDATE users SET password_hash = ?, "
            "password_version = password_version + 1 WHERE id = ?",
            (new_hash, user_id),
        )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return user_id


# --------------------------------------------------------------------------
# 登录 / 会话
# --------------------------------------------------------------------------

def login(
    conn: sqlite3.Connection, login_name: str, password: str
) -> tuple[str | None, sqlite3.Row | None]:
    """登录成功返回 (cookie 原始会话 ID, 用户行)，失败返回 (None, None)。

    慢哈希在事务外执行；通过后在写事务内复查 password_version，
    若期间发生过密码重置则拒绝签发会话（旧密码核验跨越重置的场景）。
    """
    user = find_user_by_login(conn, login_name)
    delay = get_hash_delay_seconds(conn)
    if user is None:
        # 同样消耗一次 argon2 校验时间，避免用户名枚举
        security.verify_password(security.DUMMY_HASH, password, delay)
        return None, None

    if not security.verify_password(user["password_hash"], password, delay):
        return None, None

    raw_session, session_digest = security.generate_session_id()
    now = int(time.time())
    try:
        with write_tx(conn):
            current = conn.execute(
                "SELECT password_version FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            if current is None or current["password_version"] != user["password_version"]:
                # 校验期间密码已被重置：放弃会话，事务回滚
                raise LoginRaceError()
            conn.execute(
                "INSERT INTO sessions(user_id, session_digest, created_at) "
                "VALUES(?, ?, ?)",
                (user["id"], session_digest, now),
            )
    except LoginRaceError:
        return None, None
    return raw_session, user


def resolve_session(
    conn: sqlite3.Connection, raw_session: str | None
) -> sqlite3.Row | None:
    if not raw_session:
        return None
    digest = security.digest_token(raw_session)
    return conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.session_digest = ?",
        (digest,),
    ).fetchone()


def logout(conn: sqlite3.Connection, raw_session: str | None) -> None:
    if not raw_session:
        return
    digest = security.digest_token(raw_session)
    with write_tx(conn):
        conn.execute("DELETE FROM sessions WHERE session_digest = ?", (digest,))


# --------------------------------------------------------------------------
# 演示邮箱（独立数据库）
# --------------------------------------------------------------------------

def send_reset_mail(to_email: str, reset_url: str, expires_at: int) -> None:
    ttl_minutes = settings.reset_ttl_seconds // 60
    subject = "【员工门户】找回密码链接"
    body = f"""您好，

我们收到了您的门户密码找回申请。请在 {ttl_minutes} 分钟内点击下面的链接设置新密码：

{reset_url}

链接有效期至 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))}（本地时间）。
如非本人操作，请忽略本邮件，您的密码不会发生变化。

—— 员工门户演示系统（本地演示邮箱，不会真正发送到互联网）
"""
    try:
        with get_mail_conn() as conn:
            conn.execute(
                "INSERT INTO mails(to_email, subject, body, created_at) "
                "VALUES(?, ?, ?, ?)",
                (to_email, subject, body, int(time.time())),
            )
    except sqlite3.Error:
        # 邮件投递失败不影响已经提交生效的重置链接
        pass


def list_mailboxes() -> list[str]:
    with get_mail_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT to_email FROM mails ORDER BY to_email"
        ).fetchall()
    return [r["to_email"] for r in rows]


def list_mails(email: str) -> list[sqlite3.Row]:
    with get_mail_conn() as conn:
        return conn.execute(
            "SELECT * FROM mails WHERE to_email = ? ORDER BY id DESC", (email,)
        ).fetchall()


def get_mail(mail_id: int) -> sqlite3.Row | None:
    with get_mail_conn() as conn:
        return conn.execute("SELECT * FROM mails WHERE id = ?", (mail_id,)).fetchone()
