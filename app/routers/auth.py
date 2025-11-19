# app/routers/auth.py
from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.services.unifi_session import start_login, complete_login, check_any_session_valid
from app.db import init_db

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

init_db()


# ---------------------------
# LOGIN PAGE
# ---------------------------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# ---------------------------
# STEP 1: LOGIN INIT
# ---------------------------
@router.post("/auth/login-init")
async def login_init(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False)
):
    res = start_login(username, password, remember_me)

    if not res.get("ok"):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": res}
        )

    if res.get("mfa_required"):
        # Show OTP page
        return templates.TemplateResponse(
            "otp.html",
            {
                "request": request,
                "username": username,
                "password": password,
                "remember_me": remember_me,
                "mfa_cookie": res.get("mfa_cookie"),
                "cookiejar_b64": res.get("cookiejar_b64"),
                "authenticators": res.get("authenticators", [])
            }
        )

    # No MFA → login OK
    return RedirectResponse("/", status_code=303)


# ---------------------------
# STEP 2: LOGIN COMPLETE (OTP)
# ---------------------------
@router.post("/auth/login-complete")
async def login_complete(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    token: str = Form(...),
    cookiejar_b64: str = Form(...),
    remember_me: bool = Form(False),
    mfa_cookie: str = Form(None)
):
    res = complete_login(
        username=username,
        password=password,
        token=token,
        cookiejar_b64=cookiejar_b64,
        remember_me=remember_me,
        mfa_cookie=mfa_cookie
    )

    if not res.get("ok"):
        return templates.TemplateResponse(
            "otp.html",
            {
                "request": request,
                "error": res,
                "username": username,
                "password": password,
                "remember_me": remember_me,
                "mfa_cookie": mfa_cookie,
                "cookiejar_b64": cookiejar_b64
            }
        )
    else:
        print(res)

    stored_id = res.get("db_id")
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        key="stored_session_id",
        value=str(stored_id),
        httponly=True,
        samesite="lax"
    )
    return response


# ---------------------------
# SESSION CHECK DEBUG
# ---------------------------
@router.get("/auth/session_check")
async def session_check():
    return check_any_session_valid()


@router.get("/session-expired", response_class=HTMLResponse)
def session_expired(request: Request):
    return templates.TemplateResponse("session_expired.html", {"request": request})
