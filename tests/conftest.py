"""pytest 公共夹具：把数据库指到临时目录，并关闭人为哈希延迟。"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from app import config
from app.db import get_conn, init_storage
from app import service


@contextmanager
def _override_settings(db_dir: Path):
    """frozen dataclass 用 object.__setattr__ 临时改写。"""
    saved = (config.settings.db_path, config.settings.mail_db_path)
    object.__setattr__(config.settings, "db_path", str(db_dir / "app.db"))
    object.__setattr__(config.settings, "mail_db_path", str(db_dir / "mail.db"))
    try:
        yield
    finally:
        object.__setattr__(config.settings, "db_path", saved[0])
        object.__setattr__(config.settings, "mail_db_path", saved[1])


@pytest.fixture()
def db_env(tmp_path):
    with _override_settings(tmp_path):
        init_storage()
        with get_conn() as conn:
            # 关闭哈希人为延迟，保证测试快速
            service.set_hash_delay_ms(conn, 0)
            service.seed_users(conn)
        yield tmp_path
