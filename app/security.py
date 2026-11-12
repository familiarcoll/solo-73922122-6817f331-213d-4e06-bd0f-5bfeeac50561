"""安全原语：密码哈希、随机令牌、令牌摘要、会话标识。

设计要点
--------
* 重置链接令牌使用 ``secrets.token_urlsafe`` 生成 256bit 随机串；
* 业务库里只保存令牌的 SHA-256 摘要（与密码哈希分开存储），
  即使数据库文件泄露，也无法凭摘要还原出可点击的链接；
* 会话 cookie 同样只在库里存摘要。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher

from .config import settings

# 一个固定的 dummy 哈希，用于“用户不存在”时也执行一次 verify，
# 避免通过耗时差异枚举用户名（仅演示用途，成本与正常校验一致）。
_dummy_ph = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
)
DUMMY_HASH = _dummy_ph.hash("dummy-password-never-used")


def make_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
    )


def hash_password(plain: str, delay_seconds: float) -> str:
    """计算 Argon2id 哈希。

    调用方必须保证：执行本函数期间不持有数据库写事务，
    这样人为延迟（用来模拟真实 argon2 计算耗时）不会阻塞
    其他进程申请链接 / 登录 / 查询身份。
    """
    if delay_seconds > 0:
        # 可中断的睡眠，便于演示与测试
        import time

        time.sleep(delay_seconds)
    return make_hasher().hash(plain)


def verify_password(stored_hash: str, plain: str, delay_seconds: float) -> bool:
    """校验密码，失败（含哈希格式错误）统一返回 False。"""
    if delay_seconds > 0:
        import time

        time.sleep(delay_seconds)
    try:
        return make_hasher().verify(stored_hash, plain)
    except Exception:  # noqa: BLE001 - 任何校验失败都按密码错误处理
        return False


def generate_token() -> str:
    """生成 256bit URL 安全随机令牌（重置链接用）。"""
    return secrets.token_urlsafe(32)


def digest_token(token: str) -> str:
    """令牌 / 会话标识的存储摘要（SHA-256 hex）。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_session_id() -> tuple[str, str]:
    """返回 (发给浏览器的原始会话 ID, 入库的摘要)。"""
    raw = secrets.token_urlsafe(32)
    return raw, digest_token(raw)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
