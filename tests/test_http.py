"""HTTP 端到端：申请链接 → 演示邮箱 → 打开链接 → 重置 → 旧会话失效。"""
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
        # TestClient 触发 startup 事件完成幂等建号
        with TestClient(app) as c:
            yield c


def _extract_reset_link(html: str) -> str:
    # 优先取可点击链接的 href 属性值，避免贪婪匹配吞掉后续 HTML
    m = re.search(r'href="(https?://[^"]+?/reset\?token=[A-Za-z0-9_\-]+)"', html)
    if m is None:
        m = re.search(r"(https?://\S+?/reset\?token=[A-Za-z0-9_\-]+)", html)
    assert m, "邮件页面里没有找到重置链接"
    return m.group(1) if m.lastindex else m.group(0)


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
    assert "演示邮箱" in r.text

    # 3. 在演示邮箱里找到邮件并提取链接
    r = client.get("/mail")
    assert "alice@example.test" in r.text
    r = client.get("/mail/alice@example.test")
    mail_id = re.search(r"/mail/view/(\d+)", r.text).group(1)
    r = client.get(f"/mail/view/{mail_id}")
    link = _extract_reset_link(r.text)

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
            page = c.get("/mail/bob@example.test").text
            mail_id = re.search(r"/mail/view/(\d+)", page).group(1)
            link = _extract_reset_link(c.get(f"/mail/view/{mail_id}").text)
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
    first_mail = re.search(
        r"/mail/view/(\d+)", client.get("/mail/alice@example.test").text
    ).group(1)
    old_link = _extract_reset_link(client.get(f"/mail/view/{first_mail}").text)
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


def test_hash_delay_setting_persists_and_applies(client: TestClient):
    r = client.post("/settings", data={"delay_ms": 1200}, follow_redirects=False)
    assert r.status_code == 200 and "已保存" in r.text
    with get_conn() as conn:
        assert service.get_hash_delay_seconds(conn) == pytest.approx(1.2)
