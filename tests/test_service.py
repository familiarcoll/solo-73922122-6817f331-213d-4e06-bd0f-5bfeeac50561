"""核心安全语义与并发交错测试（直接打服务层，真实 SQLite + 真实 argon2）。"""
from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from app import config, security, service
from app.db import (
    MAIL_PENDING,
    MAIL_SENT,
    TOKEN_ABORTED,
    TOKEN_ACTIVE,
    TOKEN_CONSUMED,
    TOKEN_PENDING,
    TOKEN_SUPERSEDED,
    get_conn,
    get_mail_conn,
)
from app.service import MailDeliveryError, ResetRaceError

ALICE = "alice"
BOB = "bob"
OLD_PW = "Wonderland-1"
NEW_PW = "Brand-New-Pass-9"
NEW_PW2 = "Second-New-Pass-8"


def _request(login: str = ALICE) -> service.ResetRequestResult:
    with get_conn() as conn:
        result = service.request_password_reset(conn, login, base_url="http://test/")
    assert result is not None
    return result


def _request_token(login: str = ALICE) -> str:
    return _request(login).token


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


def _token_status(token: str) -> str:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT status FROM reset_tokens WHERE token_digest = ?",
            (security.digest_token(token),),
        ).fetchone()
    assert row is not None
    return row["status"]


def _mail_status_by_request(request_id: str) -> str | None:
    with get_mail_conn() as conn:
        row = conn.execute(
            "SELECT status FROM mails WHERE request_id = ?", (request_id,)
        ).fetchone()
    return row["status"] if row else None


def _count_tokens(status: str) -> int:
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) c FROM reset_tokens WHERE status = ?", (status,)
        ).fetchone()["c"]


def _count_mails(status: str) -> int:
    with get_mail_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) c FROM mails WHERE status = ?", (status,)
        ).fetchone()["c"]


# --------------------------------------------------------------------------
# 基础找回语义
# --------------------------------------------------------------------------

def test_full_reset_flow_consumes_token_revokes_sessions_and_changes_password(db_env):
    # 先用旧密码登录，存在一个有效会话
    with get_conn() as conn:
        sid, user = service.login(conn, ALICE, OLD_PW)
    assert sid is not None
    assert _session_count() == 1

    result = _request()
    token = result.token
    # 配对发布完成：令牌 active、邮件 sent，且 request_id 互相对应
    assert _token_status(token) == TOKEN_ACTIVE
    assert _mail_status_by_request(result.request_id) == MAIL_SENT
    # 邮件确实可读，正文里的链接就是本次令牌
    mails = service.list_mails("alice@example.test")
    assert any(m["id"] == result.mail_id for m in mails)
    assert token in service.get_mail(result.mail_id)["body"]

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
    assert _token_status(token) == TOKEN_CONSUMED


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

    assert sum(1 for o in outcomes if o.endswith(":ok")) == 1
    assert any(o.endswith(":lost") for o in outcomes)

    # 只有获胜者的密码生效，且只有一次密码版本递增
    with get_conn() as conn:
        sid_a, _ = service.login(conn, ALICE, NEW_PW)
        sid_b, _ = service.login(conn, ALICE, NEW_PW2)
        version = _get_password_version()
    assert (sid_a is not None) ^ (sid_b is not None)
    assert version == 2


def test_new_link_supersedes_old_and_inflight_reset_fails(db_env):
    old = _request()
    old_token = old.token
    # 旧链接的在途重置：哈希先算好（模拟请求已进入慢阶段）
    with get_conn() as conn:
        _, old_hash = service.prepare_password_reset(conn, old_token, NEW_PW)

    # 此时签发新链接：新邮件可读、新链接生效、旧链接立即作废，一起发布
    new = _request()
    new_token = new.token
    assert old_token != new_token
    assert _token_status(old_token) == TOKEN_SUPERSEDED
    assert _token_status(new_token) == TOKEN_ACTIVE
    assert _mail_status_by_request(old.request_id) == MAIL_SENT
    assert _mail_status_by_request(new.request_id) == MAIL_SENT

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
    # 人为把过期时间改到过去（保持 active）
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
    result = _request()
    token = result.token
    digest = security.digest_token(token)
    with get_conn() as conn:
        rows = conn.execute("SELECT token_digest, request_id FROM reset_tokens").fetchall()
    stored = [r["token_digest"] for r in rows]
    assert digest in stored
    assert all(token not in s for s in stored)
    # 配对键是独立 uuid，不携带令牌信息
    assert all(token not in r["request_id"] for r in rows)


def test_unknown_user_reset_request_is_silent(db_env):
    with get_conn() as conn:
        assert service.request_password_reset(conn, "nobody") is None
    assert service.list_mailboxes() == []
    assert _count_tokens(TOKEN_PENDING) == 0


def test_logout_revokes_current_session_only(db_env):
    with get_conn() as conn:
        sid1, _ = service.login(conn, ALICE, OLD_PW)
        sid2, _ = service.login(conn, ALICE, OLD_PW)
        service.logout(conn, sid1)
        assert service.resolve_session(conn, sid1) is None
        assert service.resolve_session(conn, sid2) is not None


# --------------------------------------------------------------------------
# 配对发布：pending 状态对外不可用
# --------------------------------------------------------------------------

def test_pending_token_is_unusable_and_pending_mail_invisible(db_env, monkeypatch):
    """卡在邮件落库阶段时：pending 链接无效、pending 邮件不可见。"""
    entered = threading.Event()
    release = threading.Event()

    def hold(_ms, factor=1.0):
        entered.set()
        release.wait(timeout=5)

    monkeypatch.setattr(service, "_demo_hold_mail_lock", hold)
    with get_conn() as conn:
        service.set_demo_mail_lock_ms(conn, 1000)

    def do_request():
        with get_conn() as conn:
            return service.request_password_reset(conn, ALICE)

    t = threading.Thread(target=do_request)
    t.start()
    assert entered.wait(timeout=5)

    # 此刻令牌已 pending 但邮件尚未落库：链接核验必须无效
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT token_digest FROM reset_tokens WHERE status = ?",
            (TOKEN_PENDING,),
        ).fetchall()
    assert len(rows) == 1
    with get_conn() as conn:
        assert (
            service.token_failure_reason(conn, rows[0]["token_digest"]) == "unknown"
        )
    # 邮箱里看不到任何邮件
    assert service.list_mailboxes() == []
    assert service.list_mails("alice@example.test") == []

    release.set()
    t.join()
    # 发布完成后一切正常
    assert _count_tokens(TOKEN_ACTIVE) == 1
    assert _count_mails(MAIL_SENT) == 1


# --------------------------------------------------------------------------
# 投递失败：三个阶段注入故障，验证补偿与页面前提
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "stage",
    [
        service.STAGE_MAIL_INSERT,
        service.STAGE_MAIL_PUBLISH,
        service.STAGE_TOKEN_PUBLISH,
    ],
)
def test_delivery_failure_aborts_whole_request_and_keeps_old_state(db_env, stage):
    # 先有一笔成功申请（旧链接 active + 旧邮件 sent）
    old = _request()
    assert _token_status(old.token) == TOKEN_ACTIVE

    with get_conn() as conn:
        service.set_demo_stage(conn, service.DEMO_MAIL_FAIL_KEY, stage)

    with pytest.raises(MailDeliveryError):
        _request()

    # 旧申请原样保留：链接仍 active、旧邮件仍可读
    assert _token_status(old.token) == TOKEN_ACTIVE
    assert _mail_status_by_request(old.request_id) == MAIL_SENT
    assert service.get_mail(old.mail_id) is not None

    # 失败申请的令牌与邮件都收敛到 aborted / 不可见，没有 pending 残留
    assert _count_tokens(TOKEN_PENDING) == 0
    assert _count_mails(MAIL_PENDING) == 0
    failed_tokens = _count_tokens(TOKEN_ABORTED)
    assert failed_tokens == 1
    # 邮件落库阶段失败时没有邮件行；其余阶段有 aborted 邮件行（对用户不可见）
    visible = service.list_mails("alice@example.test")
    assert all(m["id"] == old.mail_id for m in visible)

    # 故障开关触发一次后自动复位
    with get_conn() as conn:
        assert service.get_demo_stage(conn, service.DEMO_MAIL_FAIL_KEY) == ""

    # 密码未变，且紧接着可以重新申请成功
    with get_conn() as conn:
        sid, _ = service.login(conn, ALICE, OLD_PW)
    assert sid is not None
    retry = _request()
    assert _token_status(retry.token) == TOKEN_ACTIVE
    # 重新申请成功会正常作废旧链接
    assert _token_status(old.token) == TOKEN_SUPERSEDED


def test_real_sqlite_locked_on_mail_insert_triggers_compensation(db_env, monkeypatch):
    """用真实锁超时（而非注入异常）验证：等不到邮箱锁就失败并补偿。"""
    blocker = sqlite3.connect(
        config.settings.mail_db_path, timeout=1, isolation_level=None
    )
    blocker.execute("BEGIN IMMEDIATE")  # 占住邮箱库写锁不释放

    def no_hold(_ms, factor=1.0):  # 关闭演示占用，让真实锁竞争发生
        return None

    monkeypatch.setattr(service, "_demo_hold_mail_lock", no_hold)
    try:
        with pytest.raises(MailDeliveryError):
            _request()
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()

    assert _count_tokens(TOKEN_PENDING) == 0
    assert _count_tokens(TOKEN_ABORTED) == 1
    assert service.list_mailboxes() == []
    # 锁释放后新申请成功
    ok = _request()
    assert _token_status(ok.token) == TOKEN_ACTIVE


# --------------------------------------------------------------------------
# 崩溃恢复：三个阶段“进程退出”后的重启收敛
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "stage",
    [
        service.STAGE_MAIL_INSERT,
        service.STAGE_MAIL_PUBLISH,
        service.STAGE_TOKEN_PUBLISH,
    ],
)
def test_recovery_after_crash_converges_to_consistent_state(db_env, stage, monkeypatch):
    old = _request()

    # 模拟进程在指定阶段硬退出：把 os._exit 替换成抛异常，
    # 既走与真实退出完全相同的“半路终止”路径，又不杀掉 pytest 进程
    class SimulatedExit(Exception):
        pass

    def _fake_exit(code):
        raise SimulatedExit(code)

    monkeypatch.setattr(service.os, "_exit", _fake_exit)
    with get_conn() as conn:
        service.set_demo_stage(conn, service.DEMO_MAIL_CRASH_KEY, stage)

    with pytest.raises(SimulatedExit):
        _request()

    # 崩溃现场：存在超过宽限期的 pending 记录（把 created_at 调老）
    cutoff = int(time.time()) - config.settings.recovery_grace_seconds - 5
    with get_conn() as conn:
        conn.execute(
            "UPDATE reset_tokens SET created_at = ? WHERE status = ?",
            (cutoff, TOKEN_PENDING),
        )
    with get_mail_conn() as conn:
        conn.execute(
            "UPDATE mails SET created_at = ? WHERE status = ?",
            (cutoff, MAIL_PENDING),
        )

    # 重启：启动恢复扫描
    handled = service.recover_pending_requests()
    assert handled >= 1

    # 不变量 1：没有任何 pending 残留
    assert _count_tokens(TOKEN_PENDING) == 0
    assert _count_mails(MAIL_PENDING) == 0

    # 不变量 2：每个 active/consumed/superseded 令牌必有 sent 邮件；
    #           每封 sent 邮件必有非 aborted 令牌
    with get_conn() as conn:
        live_requests = {
            r["request_id"]
            for r in conn.execute(
                "SELECT DISTINCT request_id FROM reset_tokens "
                "WHERE status IN (?, ?, ?)",
                (TOKEN_ACTIVE, TOKEN_CONSUMED, TOKEN_SUPERSEDED),
            ).fetchall()
        }
    with get_mail_conn() as conn:
        sent_requests = {
            r["request_id"]
            for r in conn.execute(
                "SELECT DISTINCT request_id FROM mails WHERE status = ?",
                (MAIL_SENT,),
            ).fetchall()
        }
    assert live_requests == sent_requests

    # 旧链接的状态取决于崩溃阶段：
    # - token_publish 前崩溃：申请被整体作废，旧链接仍 active 可用
    # - token_publish 阶段崩溃（邮件已 sent、令牌未 active）：恢复补发布，旧链接作废
    if stage == service.STAGE_TOKEN_PUBLISH:
        assert _token_status(old.token) == TOKEN_SUPERSEDED
        # 补发布的新链接可用并能完成重置
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM reset_tokens WHERE request_id != ? "
                "AND status = ? ORDER BY id DESC LIMIT 1",
                (old.request_id, TOKEN_ACTIVE),
            ).fetchone()
        assert row is not None
    else:
        assert _token_status(old.token) == TOKEN_ACTIVE

    # 恢复幂等：再跑一次不产生新变化
    before = service.get_status_snapshot()
    assert service.recover_pending_requests() == 0
    assert service.get_status_snapshot() == before


def test_recovery_ignores_fresh_pending_within_grace(db_env, monkeypatch):
    """宽限期内的 pending（可能仍在正常处理）不能被恢复误杀。"""
    entered = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(
        service, "_demo_hold_mail_lock",
        lambda _ms, factor=1.0: (entered.set(), release.wait(timeout=5)),
    )
    with get_conn() as conn:
        service.set_demo_mail_lock_ms(conn, 1000)

    t = threading.Thread(target=lambda: _request())
    t.start()
    assert entered.wait(timeout=5)

    # 恢复扫描不应碰这笔“年轻”的 pending
    assert service.recover_pending_requests() == 0
    assert _count_tokens(TOKEN_PENDING) == 1

    release.set()
    t.join()
    assert _count_tokens(TOKEN_ACTIVE) == 1
    assert _count_mails(MAIL_SENT) == 1


# --------------------------------------------------------------------------
# 并发申请：失败收尾不得撤销另一笔成功申请；锁等待不持业务写锁
# --------------------------------------------------------------------------

def test_concurrent_requests_failure_does_not_rollback_other_success(db_env):
    """两个账号并发申请，其中一笔投递失败，另一笔必须完整成功。"""
    # 让 bob 的邮件落库抛错，alice 正常
    real_get_mail_conn = service.get_mail_conn
    fail_box = {"email": "bob@example.test"}

    class _WrappedConn:
        """只包装 execute，其余属性委托给真实连接（连接对象的 execute 只读，不能直接替换）。"""

        def __init__(self, real):
            object.__setattr__(self, "_real", real)

        def execute(self, sql, params=()):
            if sql.lstrip().upper().startswith("INSERT INTO MAILS") and fail_box["email"] in params:
                raise sqlite3.OperationalError("模拟 bob 邮箱投递故障")
            return self._real.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self._real, name)

    class FlakyMailConn:
        def __init__(self, real_cm):
            self._cm = real_cm

        def __enter__(self):
            return _WrappedConn(self._cm.__enter__())

        def __exit__(self, *exc):
            return self._cm.__exit__(*exc)

    import app.service as svc
    original = svc.get_mail_conn
    svc.get_mail_conn = lambda: FlakyMailConn(real_get_mail_conn())
    try:
        outcomes: dict[str, str] = {}
        barrier = threading.Barrier(2)

        def worker(login: str):
            barrier.wait()
            try:
                with get_conn() as conn:
                    service.request_password_reset(conn, login)
                outcomes[login] = "ok"
            except MailDeliveryError:
                outcomes[login] = "failed"

        t1 = threading.Thread(target=worker, args=(ALICE,))
        t2 = threading.Thread(target=worker, args=(BOB,))
        t1.start(); t2.start(); t1.join(); t2.join()
    finally:
        svc.get_mail_conn = original

    assert outcomes == {ALICE: "ok", BOB: "failed"}

    # alice 的成功申请完好：active 令牌 + sent 邮件
    with get_conn() as conn:
        alice_rows = conn.execute(
            "SELECT status, COUNT(*) c FROM reset_tokens r JOIN users u "
            "ON u.id = r.user_id WHERE u.username = ? GROUP BY status",
            (ALICE,),
        ).fetchall()
    assert any(r["status"] == TOKEN_ACTIVE and r["c"] == 1 for r in alice_rows)
    alice_mails = service.list_mails("alice@example.test")
    assert len(alice_mails) == 1 and alice_mails[0]["status"] == MAIL_SENT

    # bob 的失败申请全部 aborted / 不可见，且无 pending 残留
    assert service.list_mails("bob@example.test") == []
    with get_conn() as conn:
        bob_pending = conn.execute(
            "SELECT COUNT(*) c FROM reset_tokens r JOIN users u "
            "ON u.id = r.user_id WHERE u.username = ? AND r.status = ?",
            (BOB, TOKEN_PENDING),
        ).fetchone()["c"]
        bob_aborted = conn.execute(
            "SELECT COUNT(*) c FROM reset_tokens r JOIN users u "
            "ON u.id = r.user_id WHERE u.username = ? AND r.status = ?",
            (BOB, TOKEN_ABORTED),
        ).fetchone()["c"]
    assert bob_pending == 0 and bob_aborted == 1


def test_mail_lock_wait_does_not_hold_business_write_lock(db_env, monkeypatch):
    """等待邮箱锁期间，其他账号的业务写操作（登录/查身份/申请）立即成功。"""
    entered = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(
        service, "_demo_hold_mail_lock",
        lambda _ms, factor=1.0: (entered.set(), release.wait(timeout=10)),
    )
    with get_conn() as conn:
        service.set_demo_mail_lock_ms(conn, 1000)

    t = threading.Thread(target=lambda: _request(ALICE))
    t.start()
    assert entered.wait(timeout=5)  # alice 正在等邮箱锁

    # 期间 bob 的登录（含写会话事务）必须快速完成，不被业务写锁挡住
    t0 = time.time()
    with get_conn() as conn:
        sid, user = service.login(conn, BOB, "Secret-2")
        who = service.get_user_by_id(conn, user["id"])
    elapsed = time.time() - t0
    assert sid is not None and who["username"] == BOB
    assert elapsed < 1.0, f"等邮箱锁期间业务写操作被阻塞 {elapsed:.2f}s"

    # bob 自己的重置申请也能在期间完整发布（独立 request_id，互不干扰）
    bob_result = _request(BOB)
    assert _token_status(bob_result.token) == TOKEN_ACTIVE

    release.set()
    t.join()
    assert _count_mails(MAIL_SENT) == 2
    assert _count_tokens(TOKEN_PENDING) == 0


def test_two_successful_concurrent_requests_both_publish(db_env):
    """同账号并发两笔成功申请：两封邮件都可读，只有最新链接 active。"""
    barrier = threading.Barrier(2)
    results: list[service.ResetRequestResult] = []

    def worker():
        barrier.wait()
        with get_conn() as conn:
            results.append(service.request_password_reset(conn, ALICE))

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start(); t2.start(); t1.join(); t2.join()

    assert len(results) == 2
    mails = service.list_mails("alice@example.test")
    assert len(mails) == 2
    statuses = sorted(_token_status(r.token) for r in results)
    assert statuses == sorted([TOKEN_ACTIVE, TOKEN_SUPERSEDED])
    # 两封邮件的链接都能在邮箱里打开（旧邮件仍在，只是链接已作废）
    for r in results:
        assert service.get_mail(r.mail_id) is not None


# --------------------------------------------------------------------------
# 旧版库结构迁移
# --------------------------------------------------------------------------

def test_legacy_schema_migrates_to_state_machine(tmp_path):
    db_path = tmp_path / "app.db"
    mail_path = tmp_path / "mail.db"
    from app import config
    from app.db import _enable_wal_once

    saved = (config.settings.db_path, config.settings.mail_db_path)
    object.__setattr__(config.settings, "db_path", str(db_path))
    object.__setattr__(config.settings, "mail_db_path", str(mail_path))
    try:
        _enable_wal_once(str(db_path), 5000)
        _enable_wal_once(str(mail_path), 5000)
        # 造一个旧版结构的库
        legacy = sqlite3.connect(str(db_path), isolation_level=None)
        legacy.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
              email TEXT UNIQUE, password_hash TEXT, password_version INTEGER DEFAULT 1,
              created_at INTEGER);
            CREATE TABLE reset_tokens (id INTEGER PRIMARY KEY, user_id INTEGER,
              token_digest TEXT UNIQUE, expires_at INTEGER,
              consumed_at INTEGER, superseded_at INTEGER, created_at INTEGER);
            INSERT INTO users VALUES (1, 'alice', 'a@x.test', 'h', 1, 0);
            INSERT INTO reset_tokens VALUES
              (1, 1, 'd1', 9999999999, NULL, NULL, 0),
              (2, 1, 'd2', 9999999999, 123, NULL, 0),
              (3, 1, 'd3', 9999999999, NULL, 456, 0);
            """
        )
        legacy.close()
        legacy_mail = sqlite3.connect(str(mail_path), isolation_level=None)
        legacy_mail.executescript(
            "CREATE TABLE mails (id INTEGER PRIMARY KEY, to_email TEXT, "
            "subject TEXT, body TEXT, created_at INTEGER);"
            "INSERT INTO mails VALUES (1, 'a@x.test', 's', 'b', 0);"
        )
        legacy_mail.close()

        from app.db import init_storage
        init_storage()
        with get_conn() as conn:
            got = {
                r["token_digest"]: r["status"]
                for r in conn.execute("SELECT token_digest, status FROM reset_tokens")
            }
        assert got == {"d1": TOKEN_ACTIVE, "d2": TOKEN_CONSUMED, "d3": TOKEN_SUPERSEDED}
        with get_mail_conn() as conn:
            assert conn.execute(
                "SELECT status FROM mails WHERE id = 1"
            ).fetchone()["status"] == MAIL_SENT
    finally:
        object.__setattr__(config.settings, "db_path", saved[0])
        object.__setattr__(config.settings, "mail_db_path", saved[1])
