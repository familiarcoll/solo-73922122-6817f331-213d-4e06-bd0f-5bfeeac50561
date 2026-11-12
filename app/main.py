"""FastAPI 路由与页面渲染。"""
from __future__ import annotations

import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import service
from .db import get_conn, init_storage
from .security import digest_token
from .service import ResetRaceError

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.filters["timestamp_fmt"] = lambda ts: time.strftime(
    "%Y-%m-%d %H:%M:%S", time.localtime(ts)
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_storage()
    with get_conn() as conn:
        created = service.seed_users(conn)
        if created:
            print(f"[startup] 预置账号就绪: {', '.join(created)}")
    yield


app = FastAPI(title="员工门户 · 密码找回演示", lifespan=lifespan)

SESSION_COOKIE = "portal_session"
URL_RE = re.compile(r"https?://[^\s]+")


# --------------------------------------------------------------------------
# 辅助
# --------------------------------------------------------------------------

def _current_user(request: Request):
    raw = request.cookies.get(SESSION_COOKIE)
    with get_conn() as conn:
        return service.resolve_session(conn, raw)


def _render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("user", _current_user(request))
    return templates.TemplateResponse(request, name, ctx)


# --------------------------------------------------------------------------
# 首页 / 健康检查
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    with get_conn() as conn:
        delay_ms = int(service.get_hash_delay_seconds(conn) * 1000)
    return _render(request, "home.html", delay_ms=delay_ms)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# 登录 / 登出 / 身份
# --------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return _render(request, "login.html", error=None)


@app.post("/login")
def login_submit(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
):
    with get_conn() as conn:
        raw_session, user = service.login(conn, login.strip(), password)
    if raw_session is None:
        return _render(
            request,
            "login.html",
            error="用户名或密码错误（也可能是在密码校验期间密码已被重置，旧密码不会签发会话）",
        )
    resp = RedirectResponse(url="/me", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, raw_session, httponly=True, samesite="lax", path="/"
    )
    return resp


@app.post("/logout")
def logout(request: Request):
    raw = request.cookies.get(SESSION_COOKIE)
    with get_conn() as conn:
        service.logout(conn, raw)
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/me", response_class=HTMLResponse)
def me(request: Request):
    user = _current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return _render(request, "me.html")


# --------------------------------------------------------------------------
# 找回密码：申请链接
# --------------------------------------------------------------------------

@app.get("/reset/request", response_class=HTMLResponse)
def reset_request_page(request: Request):
    return _render(request, "reset_request.html", sent=False, login_value="")


@app.post("/reset/request")
def reset_request_submit(request: Request, login: str = Form(...)):
    login = login.strip()
    with get_conn() as conn:
        result = service.request_password_reset(conn, login)
    if result is not None:
        # 事务提交后再拼链接并投递演示邮箱；令牌只出现在邮件里，业务库只存摘要
        final_url = f"{request.base_url}reset?token={result.token}"
        service.send_reset_mail(result.email, final_url, result.expires_at)
    # 无论账号是否存在都显示同样的提示，避免账号枚举
    return _render(
        request,
        "reset_request.html",
        sent=True,
        login_value=login,
        hint_email=result.email if result else None,
    )


# --------------------------------------------------------------------------
# 找回密码：打开链接 / 提交新密码
# --------------------------------------------------------------------------

def _reset_form(request: Request, token: str, error: str | None = None):
    with get_conn() as conn:
        reason = service.token_failure_reason(conn, digest_token(token))
    return _render(
        request,
        "reset_form.html",
        token=token,
        reason=reason,
        error=error,
    )


@app.get("/reset", response_class=HTMLResponse)
def reset_page(request: Request, token: str = ""):
    if not token:
        return _render(request, "reset_form.html", token="", reason="unknown", error=None)
    return _reset_form(request, token)


@app.post("/reset")
def reset_submit(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    # 1) 表单校验（不触碰任何状态）
    if len(new_password) < 8:
        return _reset_form(request, token, error="新密码至少需要 8 个字符")
    if new_password != confirm_password:
        return _reset_form(request, token, error="两次输入的新密码不一致")

    # 2) 慢阶段：只读核验链接 + 事务外计算 argon2 哈希（不持写锁）
    with get_conn() as conn:
        try:
            _token_row, new_hash = service.prepare_password_reset(
                conn, token, new_password
            )
        except ResetRaceError as exc:
            return _reset_form(request, token, error=_reason_text(str(exc)))

    # 3) 快阶段：单事务原子消费链接 / 换密码 / 撤销全部会话
    with get_conn() as conn:
        try:
            service.commit_password_reset(conn, token, new_hash)
        except ResetRaceError as exc:
            # 失败路径：密码、链接状态均未改变
            return _reset_form(request, token, error=_reason_text(str(exc)))

    return _render(request, "reset_done.html")


def _reason_text(reason: str) -> str:
    return {
        "consumed": "该链接已被使用过，不能重复重置",
        "superseded": "该账号已签发更新的找回链接，旧链接已作废",
        "expired": "链接已超过 10 分钟有效期",
        "unknown": "链接无效或不存在，请重新申请",
    }.get(reason, "链接当前不可用，请重新申请")


# --------------------------------------------------------------------------
# 演示邮箱
# --------------------------------------------------------------------------

@app.get("/mail", response_class=HTMLResponse)
def mailboxes(request: Request):
    return _render(request, "mailboxes.html", boxes=service.list_mailboxes())


@app.get("/mail/{email}", response_class=HTMLResponse)
def mailbox(request: Request, email: str):
    mails = service.list_mails(email)
    return _render(request, "mailbox.html", email=email, mails=mails)


@app.get("/mail/view/{mail_id}", response_class=HTMLResponse)
def mail_view(request: Request, mail_id: int):
    mail = service.get_mail(mail_id)
    if mail is None:
        return RedirectResponse(url="/mail", status_code=303)
    match = URL_RE.search(mail["body"])
    reset_link = match.group(0) if match else None
    return _render(request, "mail_view.html", mail=mail, reset_link=reset_link)


# --------------------------------------------------------------------------
# 哈希延迟调节（演示交错操作）
# --------------------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    with get_conn() as conn:
        delay_ms = int(service.get_hash_delay_seconds(conn) * 1000)
    return _render(request, "settings.html", delay_ms=delay_ms, saved=False)


@app.post("/settings")
def settings_submit(request: Request, delay_ms: int = Form(...)):
    with get_conn() as conn:
        service.set_hash_delay_ms(conn, delay_ms)
        actual = int(service.get_hash_delay_seconds(conn) * 1000)
    return _render(request, "settings.html", delay_ms=actual, saved=True)
