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
    # 启动恢复：收敛上个进程在发布中途退出留下的 pending 记录
    recovered = service.recover_pending_requests()
    if recovered:
        print(f"[startup] 恢复收敛了 {recovered} 笔未完成的找回申请")
    # 定时恢复：两个 Web 进程各自运行，按 request_id 幂等收敛，互不干扰
    recovery_thread = service.start_recovery_loop()
    try:
        yield
    finally:
        recovery_thread.stop()


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
# 找回密码：申请链接（签发与投递配对发布，失败如实报错）
# --------------------------------------------------------------------------

@app.get("/reset/request", response_class=HTMLResponse)
def reset_request_page(request: Request):
    return _render(
        request, "reset_request.html",
        sent=False, delivery_error=None, login_value="", hint_email=None,
    )


@app.post("/reset/request")
def reset_request_submit(request: Request, login: str = Form(...)):
    login = login.strip()
    delivery_error: str | None = None
    result = None
    try:
        with get_conn() as conn:
            # 令牌只出现在邮件里，业务库只存摘要；base_url 用于拼接邮件链接
            result = service.request_password_reset(
                conn, login, base_url=str(request.base_url)
            )
    except service.MailDeliveryError as exc:
        # 补偿已完成：本申请的令牌与邮件均已撤销，旧链接保持原状。
        # 页面必须如实提示失败，绝不显示“已发送”。
        delivery_error = str(exc)

    # 账号不存在时仍显示统一的中性提示，避免账号枚举
    return _render(
        request,
        "reset_request.html",
        sent=result is not None and delivery_error is None,
        delivery_error=delivery_error,
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
        request, "reset_form.html",
        token=token, reason=reason, error=error,
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
# 哈希延迟与故障演示调节（演示交错操作 / 锁等待 / 投递失败 / 发布中退出）
# --------------------------------------------------------------------------

def _settings_context(saved: bool) -> dict:
    with get_conn() as conn:
        delay_ms = int(service.get_hash_delay_seconds(conn) * 1000)
        lock_ms = service.get_demo_mail_lock_ms(conn)
        fail_stage = service.get_demo_stage(conn, service.DEMO_MAIL_FAIL_KEY)
        crash_stage = service.get_demo_stage(conn, service.DEMO_MAIL_CRASH_KEY)
    return {
        "delay_ms": delay_ms,
        "lock_ms": lock_ms,
        "fail_stage": fail_stage,
        "crash_stage": crash_stage,
        "saved": saved,
        "snapshot": service.get_status_snapshot(),
        "events": service.tail_events(),
        "stage_mail_insert": service.STAGE_MAIL_INSERT,
        "stage_mail_publish": service.STAGE_MAIL_PUBLISH,
        "stage_token_publish": service.STAGE_TOKEN_PUBLISH,
    }


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return _render(request, "settings.html", **_settings_context(saved=False))


@app.post("/settings")
def settings_submit(
    request: Request,
    delay_ms: int = Form(...),
    mail_lock_ms: int = Form(0),
    mail_fail_stage: str = Form(""),
    mail_crash_stage: str = Form(""),
):
    with get_conn() as conn:
        service.set_hash_delay_ms(conn, delay_ms)
        service.set_demo_mail_lock_ms(conn, mail_lock_ms)
        service.set_demo_stage(conn, service.DEMO_MAIL_FAIL_KEY, mail_fail_stage)
        service.set_demo_stage(conn, service.DEMO_MAIL_CRASH_KEY, mail_crash_stage)
    return _render(request, "settings.html", **_settings_context(saved=True))
