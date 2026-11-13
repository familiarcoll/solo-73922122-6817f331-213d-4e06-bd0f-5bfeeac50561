"""SQLite 连接与建表。

并发模型（满足“两个 Web 进程并发”的关键）
------------------------------------------
* 启用 WAL：多读单写互不阻塞，读者不会挡住写者；
* 每个写事务使用 ``BEGIN IMMEDIATE`` 立刻获取保留锁，
  配合各自独立的 ``busy_timeout`` 等待其他进程释放；
* 所有“一次性消费”类操作都用条件 UPDATE + 检查 rowcount，
  在同一事务内原子完成，跨进程也只能有一个赢家。

两库隔离
--------
* 业务库 ``app.db``（用户 / 令牌 / 会话 / 设置）与邮箱库 ``mail.db``
  是两个完全独立的 SQLite 文件，各有自己的锁；
* 等待邮箱库写锁期间业务库写事务早已提交，因此不持有业务库写锁，
  其他账号仍可登录、查询身份、申请重置。

崩溃恢复
--------
令牌与邮件都带 ``status`` 状态机（pending → 终态），并以 ``request_id``
配对；进程在发布中途退出后，重启时由 service 层的恢复逻辑按配对关系
把残留的 pending 记录收敛到一致终态，绝不留下
“有效链接无邮件”或“可见邮件对应未签发链接”。
"""
from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .config import settings

# 令牌 / 邮件状态机
TOKEN_PENDING = "pending"      # 已签发但尚未发布：任何链接核验都视为无效
TOKEN_ACTIVE = "active"        # 已发布：链接生效，且配对邮件已可见
TOKEN_SUPERSEDED = "superseded"
TOKEN_CONSUMED = "consumed"
TOKEN_ABORTED = "aborted"      # 投递失败 / 崩溃补偿：申请作废，链接从未生效

MAIL_PENDING = "pending"       # 已落库但不可见（投递未发布）
MAIL_SENT = "sent"             # 已发布：用户可在邮箱读取
MAIL_ABORTED = "aborted"       # 投递失败 / 崩溃补偿：对用户不可见

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    -- 每次重置密码自增；登录在写事务内复查它，防止“旧密码核验跨越重置”仍签发会话
    password_version INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    -- 一次申请的配对键，与 mail.db 中 mails.request_id 对应
    request_id   TEXT NOT NULL,
    token_digest TEXT NOT NULL UNIQUE,
    expires_at   INTEGER NOT NULL,
    -- 状态机：pending → active → (consumed | superseded)；
    -- 投递失败 / 崩溃补偿直接 pending → aborted。
    -- active 之外的状态对链接核验一律不可用。
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_request ON reset_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_status ON reset_tokens(status);

CREATE TABLE IF NOT EXISTS sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id),
    session_digest TEXT NOT NULL UNIQUE,
    created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

MAIL_SCHEMA = """
CREATE TABLE IF NOT EXISTS mails (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 与业务库 reset_tokens.request_id 配对（两库之间的逻辑关联键，非外键）
    request_id TEXT NOT NULL,
    to_email   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    -- pending 对收件人不可见；sent 才可读；aborted 为失败收尾，同样不可见
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mails_to ON mails(to_email);
CREATE INDEX IF NOT EXISTS idx_mails_request ON mails(request_id);
CREATE INDEX IF NOT EXISTS idx_mails_status ON mails(status);
"""


def _connect(path: str, busy_timeout_ms: int) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=busy_timeout_ms / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # busy_timeout 以毫秒计；锁竞争时在此窗口内等待而不是立刻报错
    conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
    # WAL 是数据库的持久属性，在 init_storage 里设置一次即可，
    # 不在每条连接上重复切换，避免与其他进程的初始化写事务撞锁
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """业务库连接（自动提交模式，事务由 service 层显式控制）。"""
    conn = _connect(settings.db_path, settings.busy_timeout_ms)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_mail_conn() -> Iterator[sqlite3.Connection]:
    """邮箱库连接，使用独立（通常更长）的锁等待超时。"""
    conn = _connect(settings.mail_db_path, settings.mail_busy_timeout_ms)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """开启 IMMEDIATE 写事务；异常回滚，正常提交。"""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _enable_wal_once(path: str, busy_timeout_ms: int) -> None:
    """把数据库切换到 WAL（持久属性）。多进程同时初始化时用 busy_timeout 等待。"""
    conn = sqlite3.connect(path, timeout=busy_timeout_ms / 1000, isolation_level=None)
    try:
        conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        conn.execute("PRAGMA journal_mode = WAL")
    finally:
        conn.close()


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate_legacy_schema(conn: sqlite3.Connection) -> None:
    """把旧版（无状态机）库结构升级到新版，幂等执行。

    旧表 reset_tokens 用 consumed_at / superseded_at 两个时间戳表达状态，
    邮件表 mails 没有状态列。迁移把既有数据映射进新状态机：
    历史令牌都已完成发布（active / consumed / superseded），
    历史邮件都视为已投递（sent）。
    """
    token_cols = _column_names(conn, "reset_tokens")
    if token_cols and "status" not in token_cols:
        # 先加列，再建索引（同一次 executescript 内索引依赖刚加的列）
        conn.execute(
            "ALTER TABLE reset_tokens ADD COLUMN request_id TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "ALTER TABLE reset_tokens ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
        )
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_reset_tokens_request ON reset_tokens(request_id);
            CREATE INDEX IF NOT EXISTS idx_reset_tokens_status ON reset_tokens(status);
            UPDATE reset_tokens
               SET status = CASE
                     WHEN consumed_at IS NOT NULL THEN 'consumed'
                     WHEN superseded_at IS NOT NULL THEN 'superseded'
                     ELSE 'active'
                   END;
            """
        )

    mail_cols = _column_names(conn, "mails")
    if mail_cols and "status" not in mail_cols:
        conn.execute(
            "ALTER TABLE mails ADD COLUMN request_id TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "ALTER TABLE mails ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'"
        )
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_mails_request ON mails(request_id);
            CREATE INDEX IF NOT EXISTS idx_mails_status ON mails(status);
            """
        )


def init_storage() -> None:
    """建表 / 迁移（幂等），并确保业务库与邮箱库处于 WAL 模式。"""
    for path, timeout_ms in (
        (settings.db_path, settings.busy_timeout_ms),
        (settings.mail_db_path, settings.mail_busy_timeout_ms),
    ):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _enable_wal_once(path, timeout_ms)
    # 先迁移旧版表结构（补列、映射状态），再执行新版 SCHEMA——
    # 新索引依赖 request_id / status 列，必须在列就位后创建
    with get_conn() as conn:
        _migrate_legacy_schema(conn)
        conn.executescript(SCHEMA)
    with get_mail_conn() as conn:
        _migrate_legacy_schema(conn)
        conn.executescript(MAIL_SCHEMA)
