"""核心安全语义与并发交错测试（直接打服务层，真实 SQLite + 真实 argon2）。"""
from __future__ import annotations

import threading
import time

import pytest

from app import security, service
from app.db import get_conn
from app.service import ResetRaceError

ALICE = "alice"
OLD_PW = "Wonderland-1"
NEW_PW = "Brand-New-Pass-9"
NEW_PW2 = "Second-New-Pass-8"


def _request_token(login: str = ALICE) -> str:
    with get_conn() as conn:
        result = service.request_password_reset(conn, login)
    assert result is not None
    return result.token


def _get_password_version() -> int:
    with get_conn() as conn:
        row = service.find_user_by_login(conn, ALICE)
        return row["password_version"]


def _session_count() -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE u.username = ?",
            (ALICE,),
        ).fetchone()
        return row["c"]


def test_full_reset_flow_consumes_token_revokes_sessions_and_changes_password(db_env):
    # 先用旧密码登录，存在一个有效会话
    with get_conn() as conn:
        sid, user = service.login(conn, ALICE, OLD_PW)
    assert sid is not None
    assert _session_count() == 1

    token = _request_token()
    with get_conn() as conn:
        token_row, new_hash = service.prepare_password_reset(conn, token, NEW_PW)
        user_id = service.commit_password_reset(conn, token, new_hash)
    assert user_id == user["id"]

    # 旧密码失效，新密码可用
    with get_conn() as conn:
        assert service.login(conn, ALICE, OLD_PW) == (None, None)
        new_sid, _ = service.login(conn, ALICE, NEW_PW)
    assert new_sid is not None

    # 旧会话被撤销，链接不可再用
    with get_conn() as conn:
        assert service.resolve_session(conn, sid) is None
        reason = service.token_failure_reason(conn, security.digest_token(token))
    assert reason == "consumed"


def test_same_token_concurrent_reset_succeeds_only_once(db_env):
    token = _request_token()
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def worker(pw: str, tag: str):
        barrier.wait()
        try:
            with get_conn() as conn:
                _, h = service.prepare_password_reset(conn, token, pw)
                service.commit_password_reset(conn, token, h)
            outcomes.append(f"{tag}:ok")
        except ResetRaceError:
            outcomes.append(f"{tag}:lost")

    t1 = threading.Thread(target=worker, args=(NEW_PW, "A"))
    t2 = threading.Thread(target=worker, args=(NEW_PW2, "B"))
    t1.start(); t2.start(); t1.join(); t2.join()

    assert sorted(outcomes).count("A:ok") + sorted(outcomes).count("B:ok") == 1
    assert any(o.endswith(":lost") for o in outcomes)

    # 只有获胜者的密码生效，且只有一次密码版本递增
    with get_conn() as conn:
        sid_a, _ = service.login(conn, ALICE, NEW_PW)
        sid_b, _ = service.login(conn, ALICE, NEW_PW2)
        version = _get_password_version()
    assert (sid_a is not None) ^ (sid_b is not None)
    assert version == 2


def test_new_link_supersedes_old_and_inflight_reset_fails(db_env):
    old_token = _request_token()
    # 旧链接的在途重置：哈希先算好（模拟请求已进入慢阶段）
    with get_conn() as conn:
        _, old_hash = service.prepare_password_reset(conn, old_token, NEW_PW)

    # 此时签发新链接，旧链接立即作废
    new_token = _request_token()
    assert old_token != new_token

    with get_conn() as conn:
        assert service.token_failure_reason(
            conn, security.digest_token(old_token)
        ) == "superseded"

    # 旧链接提交必须失败，且密码不变
    with get_conn() as conn:
        with pytest.raises(ResetRaceError):
            service.commit_password_reset(conn, old_token, old_hash)

    with get_conn() as conn:
        sid, _ = service.login(conn, ALICE, OLD_PW)
    assert sid is not None, "旧链接重置失败后旧密码仍应可登录"

    # 新链接可以正常完成重置
    with get_conn() as conn:
        _, new_hash = service.prepare_password_reset(conn, new_token, NEW_PW)
        service.commit_password_reset(conn, new_token, new_hash)
    with get_conn() as conn:
        sid, _ = service.login(conn, ALICE, NEW_PW)
    assert sid is not None


def test_login_spanning_reset_never_issues_session(db_env, monkeypatch):
    """旧密码核验若跨越重置提交，不得签发有效会话。"""
    entered = threading.Event()
    release = threading.Event()
    real_verify = security.verify_password

    def blocking_verify(stored_hash, plain, delay):
        entered.set()
        release.wait(timeout=5)
        return real_verify(stored_hash, plain, delay)

    monkeypatch.setattr(service.security, "verify_password", blocking_verify)

    def do_login():
        with get_conn() as conn:
            return service.login(conn, ALICE, OLD_PW)

    t = threading.Thread(target=do_login)
    t.start()
    assert entered.wait(timeout=5)

    # 登录线程卡在密码校验期间，另一个请求完成密码重置
    token = _request_token()
    with get_conn() as conn:
        _, h = service.prepare_password_reset(conn, token, NEW_PW)
        service.commit_password_reset(conn, token, h)

    release.set()
    t.join()

    # 没有产生任何会话；用旧密码登录彻底失败，新密码可以登录
    assert _session_count() == 0
    with get_conn() as conn:
        assert service.login(conn, ALICE, OLD_PW) == (None, None)
        sid, _ = service.login(conn, ALICE, NEW_PW)
    assert sid is not None


def test_slow_hashing_does_not_block_other_operations(db_env, monkeypatch):
    with get_conn() as conn:
        service.set_hash_delay_ms(conn, 2000)
    token = _request_token()

    # 登录走真实 argon2 校验但不吃人为延迟，避免与慢重置的 2s 哈希竞争；
    # 重置的 hash_password 仍按设置等待 2s，用来证明慢哈希期间不阻塞他人
    real_verify = security.verify_password
    monkeypatch.setattr(
        service.security,
        "verify_password",
        lambda stored, plain, _delay: real_verify(stored, plain, 0.0),
    )

    start = time.time()
    def slow_reset():
        with get_conn() as conn:
            _, h = service.prepare_password_reset(conn, token, NEW_PW)
            service.commit_password_reset(conn, token, h)

    t = threading.Thread(target=slow_reset)
    t.start()
    # 等慢哈希开始
    time.sleep(0.3)

    # 哈希期间（不持写锁）：登录、查询身份应立即得到响应。
    # 注意这里不申请新链接，以免主动作废旧令牌导致慢重置本身失败。
    t0 = time.time()
    with get_conn() as conn:
        sid, user = service.login(conn, ALICE, OLD_PW)
        again = service.get_user_by_id(conn, user["id"])
        # 只读身份查询也验证一下邮箱侧读操作不受影响
        service.list_mailboxes()
    elapsed = time.time() - t0
    t.join()

    assert sid is not None and again["username"] == ALICE
    assert elapsed < 1.0, f"哈希期间其他操作被阻塞了 {elapsed:.2f}s"
    assert time.time() - start >= 2.0

    # 慢重置最终成功，且把哈希期间签发的会话一并撤销
    assert _session_count() == 0
    with get_conn() as conn:
        assert service.resolve_session(conn, sid) is None
        new_sid, _ = service.login(conn, ALICE, NEW_PW)
    assert new_sid is not None


def test_failed_reset_changes_neither_password_nor_token_state(db_env):
    token = _request_token()

    # 未知令牌 / 已作废令牌的提交都必须失败且不留痕迹
    with get_conn() as conn:
        with pytest.raises(ResetRaceError):
            service.commit_password_reset(conn, "not-a-real-token", "x" * 30)
        row_before = conn.execute(
            "SELECT * FROM reset_tokens WHERE token_digest = ?",
            (security.digest_token(token),),
        ).fetchone()

    # 表单级失败（短密码）发生在任何写操作之前，链接仍有效
    with get_conn() as conn:
        reason = service.token_failure_reason(conn, security.digest_token(token))
    assert reason is None
    with get_conn() as conn:
        sid, _ = service.login(conn, ALICE, OLD_PW)
    assert sid is not None
    with get_conn() as conn:
        row_after = conn.execute(
            "SELECT * FROM reset_tokens WHERE token_digest = ?",
            (security.digest_token(token),),
        ).fetchone()
    assert dict(row_before) == dict(row_after)


def test_expired_token_is_rejected(db_env):
    token = _request_token()
    digest = security.digest_token(token)
    # 人为把过期时间改到过去
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE reset_tokens SET expires_at = ? WHERE token_digest = ?",
            (int(time.time()) - 1, digest),
        )
        conn.execute("COMMIT")
    with get_conn() as conn:
        assert service.token_failure_reason(conn, digest) == "expired"
        with pytest.raises(ResetRaceError):
            service.prepare_password_reset(conn, token, NEW_PW)


def test_only_token_digest_is_stored(db_env):
    token = _request_token()
    digest = security.digest_token(token)
    with get_conn() as conn:
        rows = conn.execute("SELECT token_digest FROM reset_tokens").fetchall()
    stored = [r["token_digest"] for r in rows]
    assert digest in stored
    assert all(token not in s for s in stored)


def test_unknown_user_reset_request_is_silent(db_env):
    with get_conn() as conn:
        assert service.request_password_reset(conn, "nobody") is None
    assert service.list_mailboxes() == []


def test_logout_revokes_current_session_only(db_env):
    with get_conn() as conn:
        sid1, _ = service.login(conn, ALICE, OLD_PW)
        sid2, _ = service.login(conn, ALICE, OLD_PW)
        service.logout(conn, sid1)
        assert service.resolve_session(conn, sid1) is None
        assert service.resolve_session(conn, sid2) is not None
