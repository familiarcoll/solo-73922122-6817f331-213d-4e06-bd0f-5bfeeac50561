"""业务服务层：账号、重置令牌、会话、演示邮箱。

事务边界与“签发—投递配对发布”约定
==================================
一次密码找回申请跨越两个相互独立的 SQLite 库（业务库 / 邮箱库），
无法用单事务原子提交，因此用 **状态机 + 配对发布 + 失败补偿 + 崩溃恢复**
收敛到与原子提交等价的效果：

    业务库 reset_tokens.status:      pending → active → consumed / superseded
                                            └→ aborted（投递失败 / 崩溃补偿）
    邮箱库 mails.status:             pending → sent（对收件人可见）
                                            └→ aborted（失败收尾，不可见）

流程（``request_password_reset``）：

1. 业务库短事务写入 ``pending`` 令牌——此状态下链接核验一律视为无效，
   且不动任何已发布的旧链接；事务立即提交，**随后不再持有业务库写锁**。
2. 邮箱库短事务写入 ``pending`` 邮件（等待邮箱锁就发生在这里，
   与业务库写锁无关）。
3. 配对发布：先把邮件置为 ``sent``（用户可见），再在业务库单事务里
   把本令牌置为 ``active`` 同时作废旧的 active 链接。
   因此“新邮件可读 / 新链接生效 / 旧链接作废”三者一起对外生效。
4. 任一步失败：按 ``request_id`` 只回滚本申请自己的记录到申请前状态
   （pending → aborted），绝不触碰其他申请；路由层据此明确提示投递失败，
   不会谎报“已发送”。
5. 进程在发布中途退出：残留 pending 记录由启动恢复与定时恢复按两库
   配对关系收敛，杜绝“有效链接无邮件 / 可见邮件无有效链接”。

其他约定
--------
* Argon2 哈希 / 校验（可能耗时数秒）一律在写事务 **之外** 执行；
* 一次性消费全部放进单个 ``BEGIN IMMEDIATE`` 事务，条件 UPDATE + rowcount；
* 失败路径不开启或回滚事务，重置失败不改密码或链接状态。
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass

from . import security
from .config import settings
from .db import (
    MAIL_ABORTED,
    MAIL_PENDING,
    MAIL_SENT,
    TOKEN_ABORTED,
    TOKEN_ACTIVE,
    TOKEN_CONSUMED,
    TOKEN_PENDING,
    TOKEN_SUPERSEDED,
    get_conn,
    get_mail_conn,
    write_tx,
)
logger = logging.getLogger("portal")

HASH_DELAY_KEY = "hash_delay_ms"
DEMO_MAIL_LOCK_KEY = "demo_mail_lock_ms"
DEMO_MAIL_FAIL_KEY = "demo_mail_fail_stage"
DEMO_MAIL_CRASH_KEY = "demo_mail_crash_stage"

# 恢复轮询间隔（秒）
RECOVERY_INTERVAL_SECONDS = 5

# 最近事件的内存环形日志（仅用于演示页面观察，不参与正确性）
EVENT_LOG: deque[str] = deque(maxlen=50)
_EVENT_LOCK = threading.Lock()


def log_event(message: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {message}"
    with _EVENT_LOCK:
        EVENT_LOG.append(line)
    logger.info(message)


class ResetRaceError(Exception):
    """链接在最终提交时已失效（被消费 / 被新链接作废旧 / 过期 / 未发布）。"""


class LoginRaceError(Exception):
    """密码校验通过后的复查发现密码已被重置。"""


class MailDeliveryError(Exception):
    """演示邮箱投递或配对发布失败；申请已补偿回滚到申请前状态。"""


class _DemoInjectedError(sqlite3.Error):
    """故障演示注入的 SQLite 族异常，走与真实锁/IO 错误完全相同的补偿路径。"""


# --------------------------------------------------------------------------
# 应用设置（哈希延迟、故障演示开关，均可运行时调整）
# --------------------------------------------------------------------------

def _get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute(
        "SELECT value FROM app_settings WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row is not None else default


def _set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    with write_tx(conn):
        conn.execute(
            "INSERT INTO app_settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _clear_setting(key: str) -> None:
    """用独立连接清除开关（故障触发后自动复位，避免重试持续失败 / 崩溃循环）。"""
    try:
        with get_conn() as conn:
            with write_tx(conn):
                conn.execute("DELETE FROM app_settings WHERE key = ?", (key,))
    except sqlite3.Error:
        logger.exception("清除演示开关 %s 失败", key)


def get_hash_delay_seconds(conn: sqlite3.Connection) -> float:
    row = conn.execute(
        "SELECT value FROM app_settings WHERE key = ?", (HASH_DELAY_KEY,)
    ).fetchone()
    if row is None:
        return settings.default_hash_delay_ms / 1000.0
    return int(row["value"]) / 1000.0


def set_hash_delay_ms(conn: sqlite3.Connection, delay_ms: int) -> None:
    delay_ms = max(0, min(delay_ms, 60_000))
    _set_setting(conn, HASH_DELAY_KEY, str(delay_ms))


def get_demo_mail_lock_ms(conn: sqlite3.Connection) -> int:
    try:
        return max(0, int(_get_setting(conn, DEMO_MAIL_LOCK_KEY, "0")))
    except ValueError:
        return 0


def set_demo_mail_lock_ms(conn: sqlite3.Connection, delay_ms: int) -> None:
    delay_ms = max(0, min(delay_ms, 30_000))
    _set_setting(conn, DEMO_MAIL_LOCK_KEY, str(delay_ms))


def get_demo_stage(conn: sqlite3.Connection, key: str) -> str:
    return _get_setting(conn, key, "")


def set_demo_stage(conn: sqlite3.Connection, key: str, stage: str) -> None:
    stage = stage.strip()
    if stage:
        _set_setting(conn, key, stage)
    else:
        with write_tx(conn):
            conn.execute("DELETE FROM app_settings WHERE key = ?", (key,))


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
# 故障演示：邮箱锁占用 / 投递失败 / 发布中退出
# --------------------------------------------------------------------------

def _demo_hold_mail_lock(hold_ms: int, factor: float = 1.0) -> None:
    """在后台线程占住邮箱库写锁 hold_ms * factor 毫秒，本函数立即返回。

    正式写连接随后执行 ``BEGIN IMMEDIATE`` 时锁仍被后台持有，因此会真正进入
    ``busy_timeout`` 排队：
    * hold 短于邮箱 busy_timeout：后台提前释放，正式写入排队后成功——演示锁等待；
    * hold 长于邮箱 busy_timeout：正式写入拿到 SQLITE_BUSY 失败，走补偿——
      演示投递失败。
    占用期间申请线程不持有任何业务库写锁，其他账号的业务操作不受影响。
    """
    hold_ms = int(hold_ms * factor)
    if hold_ms <= 0:
        return

    def _hold() -> None:
        blocker = sqlite3.connect(
            settings.mail_db_path, timeout=1, isolation_level=None
        )
        try:
            blocker.execute("PRAGMA busy_timeout = 1000")
            blocker.execute("BEGIN IMMEDIATE")
            log_event(f"[demo] 后台占用邮箱库写锁 {hold_ms}ms，模拟邮箱库繁忙")
            time.sleep(hold_ms / 1000.0)
            blocker.execute("COMMIT")
        except sqlite3.Error as exc:
            log_event(f"[demo] 锁占用连接异常（不影响演示）: {exc}")
        finally:
            blocker.close()

    holder = threading.Thread(target=_hold, name="demo-mail-lock", daemon=True)
    holder.start()
    # 确保后台先拿到写锁，再让正式写入去排队
    time.sleep(0.05)


def _demo_fault(stage: str, fail_stage: str, crash_stage: str) -> None:
    """在指定阶段注入失败或硬退出；开关触发一次后自动复位。"""
    if fail_stage == stage:
        _clear_setting(DEMO_MAIL_FAIL_KEY)
        log_event(f"[demo] 在 {stage} 注入投递故障，走真实补偿路径")
        raise _DemoInjectedError(f"演示故障：{stage} 阶段投递失败")
    if crash_stage == stage:
        _clear_setting(DEMO_MAIL_CRASH_KEY)
        log_event(f"[demo] 在 {stage} 模拟进程硬退出（os._exit），等待重启恢复")
        logger.flush() if hasattr(logger, "flush") else None
        os._exit(1)


# --------------------------------------------------------------------------
# 重置链接：申请（配对发布 saga）/ 状态核验 / 消费
# --------------------------------------------------------------------------

@dataclass
class ResetRequestResult:
    email: str
    token: str           # 原始令牌，仅这一次通过邮件返回
    expires_at: int
    request_id: str      # 业务库令牌与邮箱库邮件的配对键
    mail_id: int


# 发布阶段名（同时用作演示开关的取值）
STAGE_MAIL_INSERT = "mail_insert"
STAGE_MAIL_PUBLISH = "mail_publish"
STAGE_TOKEN_PUBLISH = "token_publish"


def request_password_reset(
    conn: sqlite3.Connection, login: str, base_url: str = "http://test/"
) -> ResetRequestResult | None:
    """申请重置链接：签发与投递配对发布，失败则补偿回申请前状态。

    成功返回 :class:`ResetRequestResult`；账号不存在返回 ``None``
    （不暴露账号是否存在，也不发信）；投递 / 发布失败抛
    :class:`MailDeliveryError`，此时本申请的令牌与邮件均为 aborted，
    申请前已存在的链接原样有效。
    """
    user = find_user_by_login(conn, login)
    if user is None:
        return None

    # 演示开关在入口一次性读取（短读，不持写锁）
    with get_conn() as flag_conn:
        hold_ms = get_demo_mail_lock_ms(flag_conn)
        fail_stage = get_demo_stage(flag_conn, DEMO_MAIL_FAIL_KEY)
        crash_stage = get_demo_stage(flag_conn, DEMO_MAIL_CRASH_KEY)

    now = int(time.time())
    request_id = uuid.uuid4().hex
    token = security.generate_token()
    digest = security.digest_token(token)
    expires_at = now + settings.reset_ttl_seconds
    reset_url = f"{base_url}reset?token={token}"
    subject, body = _build_mail(reset_url, expires_at)

    # ---- 阶段 1：业务库仅签发 pending 令牌（不动旧链接），随即提交 ----------
    with write_tx(conn):
        conn.execute(
            "INSERT INTO reset_tokens"
            "(user_id, request_id, token_digest, expires_at, status, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (user["id"], request_id, digest, expires_at, TOKEN_PENDING, now),
        )
    # 业务事务已提交并释放写锁；下面等待邮箱锁期间不再持有业务库写锁。
    log_event(f"申请 {request_id[:8]}：pending 令牌已签发（链接尚不可用）")

    # ---- 阶段 2：邮箱库写入 pending 邮件 -----------------------------------
    try:
        _demo_hold_mail_lock(hold_ms)
        _demo_fault(STAGE_MAIL_INSERT, fail_stage, crash_stage)
        with get_mail_conn() as mail_conn:
            with write_tx(mail_conn):
                cur = mail_conn.execute(
                    "INSERT INTO mails"
                    "(request_id, to_email, subject, body, status, created_at) "
                    "VALUES(?, ?, ?, ?, ?, ?)",
                    (request_id, user["email"], subject, body, MAIL_PENDING, now),
                )
                mail_id = cur.lastrowid
    except sqlite3.Error as exc:
        # 邮件未能落库：作废本申请的 pending 令牌即可，旧链接从未被改动
        _abort_token(request_id)
        log_event(f"申请 {request_id[:8]}：邮件落库失败，已作废令牌：{exc}")
        raise MailDeliveryError("演示邮箱暂不可用，邮件未投递，找回链接未签发") from exc

    # ---- 阶段 3a：邮件先发布（sent 后用户才可读） --------------------------
    try:
        _demo_hold_mail_lock(hold_ms, factor=0.5)
        _demo_fault(STAGE_MAIL_PUBLISH, fail_stage, crash_stage)
        with get_mail_conn() as mail_conn:
            with write_tx(mail_conn):
                cur = mail_conn.execute(
                    "UPDATE mails SET status = ? "
                    "WHERE id = ? AND status = ?",
                    (MAIL_SENT, mail_id, MAIL_PENDING),
                )
                if cur.rowcount != 1:
                    raise _DemoInjectedError("邮件发布未命中 pending 记录")
    except sqlite3.Error as exc:
        # 重读区分“提交应答丢失但实际已提交”与真失败
        if _mail_status(mail_id) == MAIL_SENT:
            log_event(f"申请 {request_id[:8]}：邮件发布应答异常，复查确认已发布")
        else:
            _abort_mail(mail_id)
            _abort_token(request_id)
            log_event(f"申请 {request_id[:8]}：邮件发布失败，已回滚整个申请：{exc}")
            raise MailDeliveryError("邮件发布失败，本次申请已撤销，请重试") from exc

    # ---- 阶段 3b：令牌发布 + 旧链接作废（单业务事务，一起对外生效） ----------
    try:
        _demo_fault(STAGE_TOKEN_PUBLISH, fail_stage, crash_stage)
        with write_tx(conn):
            cur = conn.execute(
                "UPDATE reset_tokens SET status = ? "
                "WHERE request_id = ? AND status = ?",
                (TOKEN_ACTIVE, request_id, TOKEN_PENDING),
            )
            if cur.rowcount != 1:
                # 极端情况：pending 令牌已被恢复逻辑收敛，不能继续发布
                raise _DemoInjectedError("令牌发布未命中 pending 记录")
            # 同一事务内作废该账号此前所有已发布链接；
            # 必须排除本 request_id，否则会把刚置为 active 的新链接自己作废
            conn.execute(
                "UPDATE reset_tokens SET status = ? "
                "WHERE user_id = ? AND status = ? AND request_id <> ?",
                (TOKEN_SUPERSEDED, user["id"], TOKEN_ACTIVE, request_id),
            )
    except sqlite3.Error as exc:
        # 新连接重读，区分 COMMIT 应答丢失与真失败
        if _token_status_by_request(request_id) == TOKEN_ACTIVE:
            log_event(f"申请 {request_id[:8]}：令牌发布应答异常，复查确认已生效")
        else:
            _abort_mail(mail_id)
            _abort_token(request_id)
            log_event(f"申请 {request_id[:8]}：令牌发布失败，已回滚整个申请：{exc}")
            raise MailDeliveryError("链接签发失败，已撤回邮件，本次申请已撤销") from exc

    log_event(
        f"申请 {request_id[:8]}：配对发布完成——新邮件可读、新链接生效、旧链接作废"
    )
    return ResetRequestResult(
        email=user["email"],
        token=token,
        expires_at=expires_at,
        request_id=request_id,
        mail_id=mail_id,
    )


# ---- 补偿原语：只按 request_id / mail_id 操作本申请自己的记录 --------------

def _abort_token(request_id: str) -> None:
    """pending 令牌 → aborted。业务库不可用时留给恢复流程兜底。"""
    try:
        with get_conn() as conn:
            with write_tx(conn):
                conn.execute(
                    "UPDATE reset_tokens SET status = ? "
                    "WHERE request_id = ? AND status = ?",
                    (TOKEN_ABORTED, request_id, TOKEN_PENDING),
                )
    except sqlite3.Error:
        logger.exception("作废令牌 %s 失败，等待恢复流程收敛", request_id[:8])


def _abort_mail(mail_id: int) -> None:
    """邮件 → aborted（pending / 已发布都撤回），对收件人立即不可见。"""
    try:
        with get_mail_conn() as conn:
            with write_tx(conn):
                conn.execute(
                    "UPDATE mails SET status = ? "
                    "WHERE id = ? AND status IN (?, ?)",
                    (MAIL_ABORTED, mail_id, MAIL_PENDING, MAIL_SENT),
                )
    except sqlite3.Error:
        logger.exception("撤回邮件 %s 失败，等待恢复流程收敛", mail_id)


def _mail_status(mail_id: int) -> str | None:
    with get_mail_conn() as conn:
        row = conn.execute(
            "SELECT status FROM mails WHERE id = ?", (mail_id,)
        ).fetchone()
    return row["status"] if row else None


def _token_status_by_request(request_id: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT status FROM reset_tokens WHERE request_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()
    return row["status"] if row else None


# --------------------------------------------------------------------------
# 崩溃恢复：按两库配对关系收敛残留 pending 记录
# --------------------------------------------------------------------------

def _stale_pending_request_ids(now: int) -> set[str]:
    cutoff = now - settings.recovery_grace_seconds
    ids: set[str] = set()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT request_id FROM reset_tokens "
            "WHERE status = ? AND created_at < ?",
            (TOKEN_PENDING, cutoff),
        ).fetchall()
        ids.update(r["request_id"] for r in rows if r["request_id"])
    with get_mail_conn() as conn:
        rows = conn.execute(
            "SELECT request_id FROM mails "
            "WHERE status = ? AND created_at < ?",
            (MAIL_PENDING, cutoff),
        ).fetchall()
        ids.update(r["request_id"] for r in rows if r["request_id"])
    return ids


def _reconcile_request(request_id: str) -> None:
    """把一笔申请的两库状态收敛到合法终态。

    合法终态只有两种：
    * 失败态：令牌 aborted（或不存在）且邮件 aborted（或不存在）；
    * 成功态：令牌 active/consumed/superseded 且邮件 sent。
    """
    with get_conn() as conn:
        trow = conn.execute(
            "SELECT * FROM reset_tokens WHERE request_id = ? ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()
    with get_mail_conn() as conn:
        mrow = conn.execute(
            "SELECT * FROM mails WHERE request_id = ? ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()

    t_status = trow["status"] if trow is not None else None
    m_status = mrow["status"] if mrow is not None else None

    # 已一致：成功态
    if t_status in (TOKEN_ACTIVE, TOKEN_CONSUMED, TOKEN_SUPERSEDED) and m_status == MAIL_SENT:
        return

    # 规则 1：邮件不存在 / 已撤回 → 令牌不得保持可用或待发布
    if m_status in (None, MAIL_ABORTED):
        if t_status == TOKEN_PENDING:
            _abort_token(request_id)
            log_event(f"[recovery] {request_id[:8]} 无可见邮件，作废残留令牌")
        return

    # 规则 2：令牌不存在 / 已作废 → 邮件不得可见或待投递
    if t_status in (None, TOKEN_ABORTED):
        if m_status in (MAIL_PENDING, MAIL_SENT):
            _abort_mail(mrow["id"])
            log_event(f"[recovery] {request_id[:8]} 无有效令牌，撤回残留邮件")
        return

    # 规则 3：邮件已发布、令牌仍 pending（崩溃在 3b）→ 补发布令牌并作废旧链接
    if m_status == MAIL_SENT and t_status == TOKEN_PENDING:
        with get_conn() as conn:
            with write_tx(conn):
                cur = conn.execute(
                    "UPDATE reset_tokens SET status = ? "
                    "WHERE request_id = ? AND status = ?",
                    (TOKEN_ACTIVE, request_id, TOKEN_PENDING),
                )
                if cur.rowcount == 1:
                    # 排除本 request_id：只作废该账号更早的已发布链接
                    conn.execute(
                        "UPDATE reset_tokens SET status = ? "
                        "WHERE user_id = ? AND status = ? AND request_id <> ?",
                        (TOKEN_SUPERSEDED, trow["user_id"], TOKEN_ACTIVE, request_id),
                    )
        log_event(f"[recovery] {request_id[:8]} 邮件已在，补发布令牌并作废旧链接")
        return

    # 规则 4：两边都停在 pending（崩溃在邮件发布之前）→ 双双作废
    if m_status == MAIL_PENDING and t_status == TOKEN_PENDING:
        _abort_mail(mrow["id"])
        _abort_token(request_id)
        log_event(f"[recovery] {request_id[:8]} 发布未完成，作废残留邮件与令牌")
        return

    # 规则 5：令牌已发布、邮件仍 pending（理论罕见）→ 补发布邮件
    if m_status == MAIL_PENDING and t_status in (
        TOKEN_ACTIVE,
        TOKEN_CONSUMED,
        TOKEN_SUPERSEDED,
    ):
        with get_mail_conn() as conn:
            with write_tx(conn):
                conn.execute(
                    "UPDATE mails SET status = ? WHERE id = ? AND status = ?",
                    (MAIL_SENT, mrow["id"], MAIL_PENDING),
                )
        log_event(f"[recovery] {request_id[:8]} 令牌已在，补发布邮件")
        return


def recover_pending_requests() -> int:
    """恢复入口：收敛所有超过宽限期的 pending 申请，返回处理笔数。"""
    try:
        ids = _stale_pending_request_ids(int(time.time()))
    except sqlite3.Error:
        logger.exception("扫描 pending 申请失败，下个周期重试")
        return 0
    for request_id in sorted(ids):
        try:
            _reconcile_request(request_id)
        except sqlite3.Error:
            logger.exception("恢复申请 %s 失败，下个周期重试", request_id[:8])
    return len(ids)


class _RecoveryThread(threading.Thread):
    """守护线程：周期性收敛崩溃残留，两个 Web 进程各自运行也互不冲突。"""

    def __init__(self) -> None:
        super().__init__(name="reset-recovery", daemon=True)
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.wait(RECOVERY_INTERVAL_SECONDS):
            try:
                recover_pending_requests()
            except Exception:  # noqa: BLE001 - 恢复线程永不因异常退出
                logger.exception("恢复轮询异常")


def start_recovery_loop() -> _RecoveryThread:
    thread = _RecoveryThread()
    thread.start()
    return thread


# --------------------------------------------------------------------------
# 链接核验 / 消费
# --------------------------------------------------------------------------

def token_failure_reason(
    conn: sqlite3.Connection, token_digest: str, now: int | None = None
) -> str | None:
    """返回链接不可用的原因；None 表示当前有效。

    只读检查，绝不修改任何状态——重置失败时链接状态保持不变。
    pending（未发布）/ aborted（已撤销）的链接一律按“无效”处理，
    保证发布完成之前任何链接都不可能使用。
    """
    now = int(time.time()) if now is None else now
    row = conn.execute(
        "SELECT * FROM reset_tokens WHERE token_digest = ?", (token_digest,)
    ).fetchone()
    if row is None:
        return "unknown"
    status = row["status"]
    if status == TOKEN_CONSUMED:
        return "consumed"
    if status == TOKEN_SUPERSEDED:
        return "superseded"
    if status == TOKEN_ACTIVE:
        if row["expires_at"] <= now:
            return "expired"
        return None
    # pending / aborted：从未对外生效，按未知链接处理
    return "unknown"


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

    1. 条件消费链接（仅当仍为 active 且未过期）；
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
            "UPDATE reset_tokens SET status = ? "
            "WHERE token_digest = ? AND status = ? AND expires_at > ?",
            (TOKEN_CONSUMED, digest, TOKEN_ACTIVE, now),
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
# 演示邮箱（独立数据库；只有 sent 邮件对用户可见）
# --------------------------------------------------------------------------

def _build_mail(reset_url: str, expires_at: int) -> tuple[str, str]:
    ttl_minutes = settings.reset_ttl_seconds // 60
    subject = "【员工门户】找回密码链接"
    body = f"""您好，

我们收到了您的门户密码找回申请。请在 {ttl_minutes} 分钟内点击下面的链接设置新密码：

{reset_url}

链接有效期至 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))}（本地时间）。
如非本人操作，请忽略本邮件，您的密码不会发生变化。

—— 员工门户演示系统（本地演示邮箱，不会真正发送到互联网）
"""
    return subject, body


def list_mailboxes() -> list[str]:
    with get_mail_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT to_email FROM mails WHERE status = ? "
            "ORDER BY to_email",
            (MAIL_SENT,),
        ).fetchall()
    return [r["to_email"] for r in rows]


def list_mails(email: str) -> list[sqlite3.Row]:
    with get_mail_conn() as conn:
        return conn.execute(
            "SELECT * FROM mails WHERE to_email = ? AND status = ? ORDER BY id DESC",
            (email, MAIL_SENT),
        ).fetchall()


def get_mail(mail_id: int) -> sqlite3.Row | None:
    with get_mail_conn() as conn:
        return conn.execute(
            "SELECT * FROM mails WHERE id = ? AND status = ?",
            (mail_id, MAIL_SENT),
        ).fetchone()


# --------------------------------------------------------------------------
# 演示状态快照（设置页观察用）
# --------------------------------------------------------------------------

def get_status_snapshot() -> dict[str, dict[str, int]]:
    snapshot = {"tokens": {}, "mails": {}}
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) c FROM reset_tokens GROUP BY status"
        ).fetchall()
        snapshot["tokens"] = {r["status"]: r["c"] for r in rows}
    with get_mail_conn() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) c FROM mails GROUP BY status"
        ).fetchall()
        snapshot["mails"] = {r["status"]: r["c"] for r in rows}
    return snapshot


def tail_events(limit: int = 15) -> list[str]:
    with _EVENT_LOCK:
        return list(EVENT_LOG)[-limit:][::-1]
