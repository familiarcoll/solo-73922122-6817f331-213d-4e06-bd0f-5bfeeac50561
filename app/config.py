"""应用配置。

所有可调项均通过环境变量覆盖，Docker Compose 里给出默认值。
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    # 业务数据库（用户 / 重置令牌 / 会话 / 应用设置）
    db_path: str = os.environ.get("APP_DB_PATH", "/data/app.db")
    # 演示邮箱数据库（与业务库完全隔离）
    mail_db_path: str = os.environ.get("MAIL_DB_PATH", "/data/mail.db")

    # 重置链接有效期（秒）
    reset_ttl_seconds: int = _int("RESET_TTL_SECONDS", 10 * 60)

    # 哈希人为延迟默认值（秒），可在“哈希延迟”页面运行时调整，用于演示交错操作
    default_hash_delay_ms: int = _int("HASH_DELAY_MS", 4000)

    # 邮箱库写锁等待上限（毫秒）。超时即视为投递失败，走补偿而不是假报已发送。
    mail_busy_timeout_ms: int = _int("MAIL_BUSY_TIMEOUT_MS", 5000)

    # 业务库写锁等待上限（毫秒）。业务事务都极短（慢哈希在事务外）。
    busy_timeout_ms: int = _int("BUSY_TIMEOUT_MS", 5000)

    # 恢复宽限期（秒）：超过该时长仍停留在 pending 的“申请”视为崩溃残留。
    # 正常申请的 pending 只存在毫秒级；等待邮箱锁最多 mail_busy_timeout_ms。
    recovery_grace_seconds: int = _int("RECOVERY_GRACE_SECONDS", 20)

    # 预置账号
    seed_users: tuple[tuple[str, str, str], ...] = (
        ("alice", "alice@example.test", "Wonderland-1"),
        ("bob", "bob@example.test", "Secret-2"),
    )

    # Argon2id 参数：演示环境保持轻量，安全性仍由 argon2-cffi 保证
    argon2_time_cost: int = _int("ARGON2_TIME_COST", 2)
    argon2_memory_cost: int = _int("ARGON2_MEMORY_COST", 64 * 1024)
    argon2_parallelism: int = _int("ARGON2_PARALLELISM", 2)


settings = Settings()
