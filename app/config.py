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
