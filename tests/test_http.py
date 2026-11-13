"""HTTP 端到端：申请链接 → 演示邮箱 → 打开链接 → 重置 → 旧会话失效。

另含投递失败页面语义、发布中退出后的重启恢复等端到端验证。
"""
from __future__ import annotations

import re
import threading

import pytest
from fastapi.testclient import TestClient

from app import service
from app.db import get_conn, init_storage
from app.main import app
from conftest import _override_settings


@pytest.fixture()
def client(tmp_path):
    with _override_settings(tmp_path):
        init_storage()
        with get_conn() as conn:
            service.set_hash_delay_ms(conn, 0)
        # TestClient 触发 startup 事件完成幂等建号与启动恢复
        with TestClient(app) as c:
            yield c


def _extract_reset_link(html: str) -> str:
    # 优先取可点击链接的 href 属性值，避免贪婪匹配吞掉后续 HTML
    m = re.search(r'href="(https?://[^"]+?/reset\?token=[A-Za-z0-9_\-]+)"', html)
    if m is None:
        m = re.search(r"(https?://\S+?/reset\?token=[A-Za-z0-9_\-]+)", html)
    assert m, "邮件页面里没有找到重置链接"
    return m.group(1) if m.lastindex else m.group(0)


def _latest_mail_link(c: TestClient, email: str) -> tuple[str, str]:
    page = c.get(f"/mail/{email}").text
    mail_id = re.search(r"/mail/view/(\d+)", page).group(1)
    link = _extract_reset_link(c.get(f"/mail/view/{mail_id}").text)
    return mail_id, link


def test_browser_full_reset_journey(client: TestClient):
    # 1. 旧密码登录并访问身份页
    r = client.post(
        "/login", data={"login": "alice", "password": "Wonderland-1"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    cookie = r.headers["set-cookie"]
    assert "httponly" in cookie.lower()
    assert client.get("/me").status_code == 200

    # 2. 申请找回链接
    r = client.post("/reset/request", data={"login": "alice"})
    assert r.status_code == 200
    assert "演示邮箱" in r.text and "已发送" in r.text

    # 3. 在演示邮箱里找到邮件并提取链接
    r = client.get("/mail")
    assert "alice@example.test" in r.text
    _mail_id, link = _latest_mail_link(client, "alice@example.test")

    # 4. 打开链接是表单页
    r = client.get(link)
    assert r.status_code == 200
    assert "设置新密码" in r.text

    # 5. 提交新密码
    r = client.post(
        "/reset",
        data={"token": link.split("token=")[1],
              "new_password": "Brand-New-Pass-9",
              "confirm_password": "Brand-New-Pass-9"},
    )
    assert "密码重置成功" in r.text

    # 6. 旧会话已撤销、旧密码失败、新密码可登录
    assert client.get("/me", follow_redirects=False).status_code == 303
    r = client.post("/login", data={"login": "alice", "password": "Wonderland-1"})
    assert r.status_code == 200 and "错误" in r.text
    r = client.post(
        "/login", data={"login": "alice", "password": "Brand-New-Pass-9"},
        follow_redirects=False,
    )
    assert r.status_code == 303

    # 7. 链接不可二次使用
    r = client.get(link)
    assert "已被使用过" in r.text


def test_http_concurrent_same_link_single_winner(tmp_path):
    with _override_settings(tmp_path):
        init_storage()
        with get_conn() as conn:
            service.set_hash_delay_ms(conn, 0)

        with TestClient(app) as c:
            c.post("/reset/request", data={"login": "bob"})
            _mail_id, link = _latest_mail_link(c, "bob@example.test")
            token = link.split("token=")[1]

        # 两个独立客户端（各自独立连接，模拟两个 web 进程）并发提交同一链接
        results: list[int] = []
        barrier = threading.Barrier(2)

        def worker(pw: str):
            with TestClient(app) as local:
                barrier.wait()
                r = local.post("/reset", data={
                    "token": token, "new_password": pw, "confirm_password": pw,
                })
                results.append(1 if "密码重置成功" in r.text else 0)

        t1 = threading.Thread(target=worker, args=("Concurrency-A-1",))
        t2 = threading.Thread(target=worker, args=("Concurrency-B-2",))
        t1.start(); t2.start(); t1.join(); t2.join()

        assert sum(results) == 1  # 只有一个成功页


def test_superseded_link_page_and_submit_fail(client: TestClient):
    client.post("/reset/request", data={"login": "alice"})
    _first_id, old_link = _latest_mail_link(client, "alice@example.test")
    old_token = old_link.split("token=")[1]

    # 再次申请，旧链接作废；邮箱里有两封邮件
    client.post("/reset/request", data={"login": "alice"})
    assert "已作废" in client.get(old_link).text
    r = client.post("/reset", data={
        "token": old_token,
        "new_password": "Should-Not-Work-1",
        "confirm_password": "Should-Not-Work-1",
    })
    assert "已作废" in r.text
    # 旧密码仍然有效，证明失败没有改动密码
    r = client.post(
        "/login", data={"login": "alice", "password": "Wonderland-1"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # 两封邮件都仍可在邮箱读取
    assert len(re.findall(r"/mail/view/\d+", client.get("/mail/alice@example.test").text)) == 2


def test_hash_delay_setting_persists_and_applies(client: TestClient):
    r = client.post(
        "/settings",
        data={
            "delay_ms": 1200, "mail_lock_ms": 0,
            "mail_fail_stage": "", "mail_crash_stage": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200 and "已保存" in r.text
    with get_conn() as conn:
        assert service.get_hash_delay_seconds(conn) == pytest.approx(1.2)


@pytest.mark.parametrize(
    "stage",
    [
        service.STAGE_MAIL_INSERT,
        service.STAGE_MAIL_PUBLISH,
        service.STAGE_TOKEN_PUBLISH,
    ],
)
def test_delivery_failure_page_reports_error_and_no_mail_visible(client: TestClient, stage):
    # 先有一笔成功申请
    client.post("/reset/request", data={"login": "alice"})
    _old_id, old_link = _latest_mail_link(client, "alice@example.test")

    # 开启一次性故障
    client.post(
        "/settings",
        data={
            "delay_ms": 0, "mail_lock_ms": 0,
            "mail_fail_stage": stage, "mail_crash_stage": "",
        },
    )
    r = client.post("/reset/request", data={"login": "alice"})
    # 页面必须明确失败，绝不能出现“已发送”
    assert r.status_code == 200
    assert "投递失败" in r.text
    assert "已发送" not in r.text

    # 邮箱里仍只有旧的一封，失败邮件不可见
    page = client.get("/mail/alice@example.test").text
    assert len(re.findall(r"/mail/view/\d+", page)) == 1

    # 旧链接仍有效；故障开关已自动复位，再次申请成功
    assert "设置新密码" in client.get(old_link).text
    r = client.post("/reset/request", data={"login": "alice"})
    assert "已发送" in r.text
    # 新申请作废旧链接
    assert "已作废" in client.get(old_link).text


def test_mail_lock_timeout_reports_failure_and_compensates(client: TestClient):
    # 占用 8 秒 > 邮箱 busy_timeout 5 秒：必然投递失败
    client.post(
        "/settings",
        data={
            "delay_ms": 0, "mail_lock_ms": 8000,
            "mail_fail_stage": "", "mail_crash_stage": "",
        },
    )
    r = client.post("/reset/request", data={"login": "bob"})
    assert "投递失败" in r.text
    assert "已发送" not in r.text
    # 邮箱无邮件，业务库无 pending/active 新链接
    assert "暂无邮件" in client.get("/mail/bob@example.test").text
    # 关闭锁占用后可正常申请
    client.post(
        "/settings",
        data={
            "delay_ms": 0, "mail_lock_ms": 0,
            "mail_fail_stage": "", "mail_crash_stage": "",
        },
    )
    r = client.post("/reset/request", data={"login": "bob"})
    assert "已发送" in r.text
    _id, link = _latest_mail_link(client, "bob@example.test")
    assert "设置新密码" in client.get(link).text


def test_mail_lock_wait_does_not_block_other_account(client: TestClient):
    # 占用 2 秒（小于超时）：alice 申请会等待后成功
    client.post(
        "/settings",
        data={
            "delay_ms": 0, "mail_lock_ms": 2000,
            "mail_fail_stage": "", "mail_crash_stage": "",
        },
    )
    done = threading.Event()

    def slow_request():
        client.post("/reset/request", data={"login": "alice"})
        done.set()

    t = threading.Thread(target=slow_request)
    t.start()
    # 等待 alice 进入邮箱锁等待
    assert done.wait(timeout=1.5) is False

    # bob 的登录与身份查询必须立即响应（不持业务库写锁）
    import time as _time
    t0 = _time.time()
    r = client.post(
        "/login", data={"login": "bob", "password": "Secret-2"},
        follow_redirects=False,
    )
    elapsed = _time.time() - t0
    assert r.status_code == 303 and elapsed < 1.0

    assert done.wait(timeout=5)
    t.join()
    _id, link = _latest_mail_link(client, "alice@example.test")
    assert "设置新密码" in client.get(link).text


def test_crash_before_token_publish_recovers_without_live_link_without_mail(
    client: TestClient, tmp_path
):
    """发布中进程退出：重启恢复后不存在“有效链接无邮件 / 可见邮件无有效链接”。"""
    # 阶段 3：邮件已 sent、令牌仍 pending 时硬退出
    client.post(
        "/settings",
        data={
            "delay_ms": 0, "mail_lock_ms": 0,
            "mail_fail_stage": "",
            "mail_crash_stage": service.STAGE_TOKEN_PUBLISH,
        },
    )
    # TestClient 在同进程内调用 os._exit 会杀掉测试进程，因此直接模拟
    # “崩溃现场”：手动构造 request_id 配对的 sent 邮件 + pending 令牌
    import sqlite3
    import uuid

    from app import config
    from app.security import digest_token, generate_token

    request_id = uuid.uuid4().hex
    token = generate_token()
    now = 1  # 远古时间戳，确保超过恢复宽限期
    with get_conn() as conn:
        user = service.find_user_by_login(conn, "alice")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO reset_tokens"
            "(user_id, request_id, token_digest, expires_at, status, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (user["id"], request_id, digest_token(token), 9_999_999_999,
             "pending", now),
        )
        conn.execute("COMMIT")
    with sqlite3.connect(config.settings.mail_db_path, isolation_level=None) as mc:
        mc.execute(
            "INSERT INTO mails(request_id, to_email, subject, body, status, created_at)"
            " VALUES(?, ?, ?, ?, ?, ?)",
            (request_id, "alice@example.test", "s",
             "http://test/reset?token=x", "sent", now),
        )

    # 模拟重启：新 TestClient 触发 startup 恢复（lifespan 退出即完成启动恢复）
    with TestClient(app):
        pass

    # 恢复后令牌被补发布为 active（与 sent 邮件配对），链接可用
    with get_conn() as conn:
        row = conn.execute(
            "SELECT status FROM reset_tokens WHERE request_id = ?", (request_id,)
        ).fetchone()
    assert row["status"] == "active"
    with sqlite3.connect(config.settings.mail_db_path) as mc:
        assert mc.execute(
            "SELECT status FROM mails WHERE request_id = ?", (request_id,)
        ).fetchone()[0] == "sent"
    # 端到端：该链接确实能打开并完成改密
    with TestClient(app) as c3:
        r = c3.get(f"http://test/reset?token={token}")
        assert "设置新密码" in r.text
        r = c3.post("/reset", data={
            "token": token,
            "new_password": "Recovered-Pass-3",
            "confirm_password": "Recovered-Pass-3",
        })
        assert "密码重置成功" in r.text


def test_crash_before_mail_publish_recovers_to_abort(client: TestClient):
    """邮件发布前崩溃（两边都 pending）：恢复后双双作废，无可见邮件、无有效链接。"""
    import sqlite3
    import uuid

    from app import config
    from app.security import digest_token, generate_token

    request_id = uuid.uuid4().hex
    token = generate_token()
    with get_conn() as conn:
        user = service.find_user_by_login(conn, "bob")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO reset_tokens"
            "(user_id, request_id, token_digest, expires_at, status, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (user["id"], request_id, digest_token(token), 9_999_999_999,
             "pending", 1),
        )
        conn.execute("COMMIT")
    with sqlite3.connect(config.settings.mail_db_path, isolation_level=None) as mc:
        mc.execute(
            "INSERT INTO mails(request_id, to_email, subject, body, status, created_at)"
            " VALUES(?, ?, ?, ?, ?, ?)",
            (request_id, "bob@example.test", "s", "b", "pending", 1),
        )

    with TestClient(app):
        pass

    with get_conn() as conn:
        assert conn.execute(
            "SELECT status FROM reset_tokens WHERE request_id = ?", (request_id,)
        ).fetchone()["status"] == "aborted"
    with sqlite3.connect(config.settings.mail_db_path) as mc:
        assert mc.execute(
            "SELECT status FROM mails WHERE request_id = ?", (request_id,)
        ).fetchone()[0] == "aborted"
    # 崩溃申请的邮件对用户不可见，链接无效
    with TestClient(app) as c:
        assert "暂无邮件" in c.get("/mail/bob@example.test").text
        assert "链接无效或不存在" in c.get(f"/reset?token={token}").text


def test_unknown_user_still_shows_neutral_message(client: TestClient):
    r = client.post("/reset/request", data={"login": "ghost"})
    assert r.status_code == 200
    # 中性提示：不出现任何账号专属的邮箱提示（hint_email 仅在账号存在时渲染），
    # 也没有投递失败错误框，也没有任何邮件产生
    assert "一封含找回链接的邮件已发送到注册邮箱" not in r.text
    assert "投递失败，本次申请未生效" not in r.text
    page = client.get("/mail").text
    assert "暂无邮件" in page
