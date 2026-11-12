"""SQLite 连接与建表。

并发模型（满足“两个 Web 进程并发”的关键）
------------------------------------------
* 启用 WAL：多读单写互不阻塞，读者不会挡住写者；
* 每个写事务使用 ``BEGIN IMMEDIATE`` 立刻获取保留锁，
  配合 ``busy_timeout`` 等待其他进程释放；
* 所有“一次性消费”类操作都用条件 UPDATE + 检查 rowcount，
  在同一事务内原子完成，跨进程也只能有一个赢家。
"""
from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .config import settings

# 锁等待 5 秒：argon2 哈希在事务之外完成，事务本身极短
BUSY_TIMEOUT_MS = 5000

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
    token_digest TEXT NOT NULL UNIQUE,
    expires_at   INTEGER NOT NULL,
    consumed_at  INTEGER,
    superseded_at INTEGER,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON reset_tokens(user_id);

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
    to_email   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mails_to ON mails(to_email);
"""


def _connect(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # busy_timeout 以毫秒计；锁竞争时在此窗口内等待而不是立刻报错
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    # WAL 是数据库的持久属性，在 init_storage 里设置一次即可，
    # 不在每条连接上重复切换，避免与其他进程的初始化写事务撞锁
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """业务库连接（自动提交模式，事务由 service 层显式控制）。"""
    conn = _connect(settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_mail_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect(settings.mail_db_path)
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


def _enable_wal_once(path: str) -> None:
    """把数据库切换到 WAL（持久属性）。多进程同时初始化时用 busy_timeout 等待。"""
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    try:
        conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode = WAL")
    finally:
        conn.close()


def init_storage() -> None:
    """建表（幂等），并确保业务库与邮箱库处于 WAL 模式。"""
    for path in (settings.db_path, settings.mail_db_path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _enable_wal_once(path)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
    with get_mail_conn() as conn:
        conn.executescript(MAIL_SCHEMA)
