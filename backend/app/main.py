import json
import os
import threading
import hmac
import hashlib
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////data/panel.db")
PROXY_CONFIG_PATH = Path(os.environ.get("PROXY_CONFIG_PATH", "/opt/proxy/conf/3proxy.cfg"))
PROXY_LOG_PATH = Path(os.environ.get("PROXY_LOG_PATH", "/opt/proxy/logs/traffic.log"))
BACKUP_DIR = Path("/data/backups")
PANEL_SECRET_KEY = os.environ.get("PANEL_SECRET_KEY", "change-me-in-production")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
PROXY_PUBLIC_HOST = os.environ.get("PROXY_PUBLIC_HOST", "auto")
PROXY_PUBLIC_SOCKS_PORT = int(os.environ.get("PROXY_PUBLIC_SOCKS_PORT", "11080"))
PROXY_PUBLIC_HTTP_PORT = int(os.environ.get("PROXY_PUBLIC_HTTP_PORT", "13128"))
PROXY_LOGDUMP_BYTES = int(os.environ.get("PROXY_LOGDUMP_BYTES", "65536"))
TRAFFIC_POLL_INTERVAL_SECONDS = float(os.environ.get("TRAFFIC_POLL_INTERVAL_SECONDS", "2.0"))
SESSION_COOKIE_NAME = "panel_session"
SESSION_TTL_SECONDS = 12 * 60 * 60


class Base(DeclarativeBase):
    pass


class ProxyUser(Base):
    __tablename__ = "proxy_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(128))
    allow_http: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_socks5: Mapped[bool] = mapped_column(Boolean, default=True)
    traffic_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_bytes: Mapped[int] = mapped_column(Integer, default=0)
    requests_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class TrafficState(Base):
    __tablename__ = "traffic_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    file_offset: Mapped[int] = mapped_column(Integer, default=0)


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

templates = Jinja2Templates(directory="/app/templates")


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=3, max_length=128)
    allow_http: bool = True
    allow_socks5: bool = True

    @field_validator("username")
    @classmethod
    def username_clean(cls, value: str) -> str:
        value = value.strip()
        if ":" in value or "|" in value or " " in value:
            raise ValueError("username must not contain spaces, ':' or '|'")
        return value

    @field_validator("password")
    @classmethod
    def password_clean(cls, value: str) -> str:
        if ":" in value or "|" in value:
            raise ValueError("password must not contain ':' or '|'")
        return value

    @field_validator("allow_socks5", "allow_http")
    @classmethod
    def protocol_guard(cls, value: bool) -> bool:
        return value


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=3, max_length=128)
    allow_http: bool | None = None
    allow_socks5: bool | None = None

    @field_validator("password")
    @classmethod
    def password_clean(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if ":" in value or "|" in value:
            raise ValueError("password must not contain ':' or '|'")
        return value


class UserOut(BaseModel):
    id: int
    username: str
    password: str
    allow_http: bool
    allow_socks5: bool
    traffic_in_bytes: int
    traffic_out_bytes: int
    traffic_bytes: int
    requests_count: int
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(proxy_users)")).fetchall()]
        if "traffic_in_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_in_bytes INTEGER DEFAULT 0"))
        if "traffic_out_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_out_bytes INTEGER DEFAULT 0"))
        conn.execute(
            text(
                "UPDATE proxy_users "
                "SET traffic_out_bytes = traffic_bytes "
                "WHERE traffic_bytes > 0 AND traffic_in_bytes = 0 AND traffic_out_bytes = 0"
            )
        )
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as session:
        state = session.get(TrafficState, 1)
        if state is None:
            session.add(TrafficState(id=1, file_offset=0))
            session.commit()


def get_db():
    with SessionLocal() as session:
        yield session


def render_proxy_config(users: list[ProxyUser]) -> str:
    users_line = []
    http_users = []
    socks_users = []

    for user in users:
        users_line.append(f"{user.username}:CL:{user.password}")
        if user.allow_http:
            http_users.append(user.username)
        if user.allow_socks5:
            socks_users.append(user.username)

    if not users_line:
        users_line.append("disabled_user:CL:disabled_password")

    http_acl = ",".join(http_users) if http_users else "__none__"
    socks_acl = ",".join(socks_users) if socks_users else "__none__"

    # Log format: epoch|username|bytes_in|bytes_out|service
    return f"""monitor /etc/3proxy/3proxy.cfg
log /var/log/3proxy/traffic.log
logformat "%t|%U|%I|%O"
# Emit intermediate records for long-lived connections,
# so panel counters update before the connection is closed.
logdump {PROXY_LOGDUMP_BYTES} {PROXY_LOGDUMP_BYTES}
rotate 7
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536
auth strong
users {" ".join(users_line)}

flush
allow {http_acl}
proxy -p3128 -a

flush
allow {socks_acl}
socks -p1080

flush
deny *
"""


def sync_proxy_config(session: Session) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    content = render_proxy_config(users)
    PROXY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = PROXY_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(PROXY_CONFIG_PATH)


def parse_traffic_line(line: str) -> tuple[str, int, int] | None:
    parts = line.strip().split("|")
    if len(parts) != 4:
        return None
    _ts, username, incoming, outgoing = parts
    if not username or username == "-":
        return None
    try:
        in_bytes = int(incoming)
        out_bytes = int(outgoing)
    except ValueError:
        return None
    return username, in_bytes, out_bytes


def traffic_worker(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            PROXY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if not PROXY_LOG_PATH.exists():
                PROXY_LOG_PATH.touch()

            with SessionLocal() as session:
                state = session.get(TrafficState, 1)
                if state is None:
                    state = TrafficState(id=1, file_offset=0)
                    session.add(state)
                    session.commit()

                with PROXY_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as log_file:
                    file_size = PROXY_LOG_PATH.stat().st_size
                    if state.file_offset > file_size:
                        state.file_offset = 0
                    log_file.seek(state.file_offset)

                    pending: dict[str, tuple[int, int, int]] = {}
                    while True:
                        line = log_file.readline()
                        if not line:
                            break
                        parsed = parse_traffic_line(line)
                        if parsed is None:
                            continue
                        username, in_bytes, out_bytes = parsed
                        req_count, traffic_in, traffic_out = pending.get(username, (0, 0, 0))
                        pending[username] = (req_count + 1, traffic_in + in_bytes, traffic_out + out_bytes)

                    state.file_offset = log_file.tell()

                    if pending:
                        users = session.scalars(select(ProxyUser).where(ProxyUser.username.in_(list(pending.keys())))).all()
                        for user in users:
                            req_count, traffic_in, traffic_out = pending[user.username]
                            user.requests_count += req_count
                            user.traffic_in_bytes += traffic_in
                            user.traffic_out_bytes += traffic_out
                            user.traffic_bytes += traffic_in + traffic_out

                    session.commit()
        except Exception:
            # Worker must survive temporary file/db errors.
            pass
        stop_event.wait(TRAFFIC_POLL_INTERVAL_SECONDS)


def validate_protocol_selection(allow_http: bool, allow_socks5: bool) -> None:
    if not allow_http and not allow_socks5:
        raise HTTPException(status_code=400, detail="At least one protocol must be enabled")


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _sign_value(value: str) -> str:
    return hmac.new(PANEL_SECRET_KEY.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_cookie(username: str) -> str:
    payload = {"u": username, "exp": _now_ts() + SESSION_TTL_SECONDS}
    payload_raw = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_raw.encode("utf-8")).decode("utf-8").rstrip("=")
    signature = _sign_value(payload_b64)
    return f"{payload_b64}.{signature}"


def decode_session_cookie(cookie_value: str | None) -> str | None:
    if not cookie_value or "." not in cookie_value:
        return None
    payload_b64, signature = cookie_value.split(".", 1)
    expected_signature = _sign_value(payload_b64)
    if not hmac.compare_digest(expected_signature, signature):
        return None
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        payload_raw = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_raw)
    except Exception:
        return None
    if payload.get("exp", 0) < _now_ts():
        return None
    return str(payload.get("u", ""))


def require_auth(request: Request) -> str:
    username = decode_session_cookie(request.cookies.get(SESSION_COOKIE_NAME))
    if username != ADMIN_USERNAME:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return username


def dump_users(session: Session) -> dict:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    items = []
    for user in users:
        items.append(
            {
                "username": user.username,
                "password": user.password,
                "allow_http": user.allow_http,
                "allow_socks5": user.allow_socks5,
                "traffic_in_bytes": user.traffic_in_bytes,
                "traffic_out_bytes": user.traffic_out_bytes,
                "traffic_bytes": user.traffic_bytes,
                "requests_count": user.requests_count,
                "created_at": user.created_at.isoformat(),
            }
        )
    return {"version": 1, "users": items}


stop_event = threading.Event()
worker_thread: threading.Thread | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global worker_thread
    init_db()
    with SessionLocal() as session:
        sync_proxy_config(session)
    stop_event.clear()
    worker_thread = threading.Thread(target=traffic_worker, args=(stop_event,), daemon=True)
    worker_thread.start()
    yield
    stop_event.set()
    if worker_thread and worker_thread.is_alive():
        worker_thread.join(timeout=2)


app = FastAPI(title="Proxy Admin Panel", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="/app/static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response):
    if payload.username != ADMIN_USERNAME or not hmac.compare_digest(payload.password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    cookie_value = make_session_cookie(payload.username)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_value,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    return {"status": "ok"}


@app.post("/api/auth/logout")
def logout(response: Response, _auth: str = Depends(require_auth)):
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "ok"}


@app.get("/api/auth/me")
def auth_me(_auth: str = Depends(require_auth)):
    return {"authenticated": True, "username": ADMIN_USERNAME}


@app.get("/api/meta")
def meta(request: Request, _auth: str = Depends(require_auth)):
    host_value = PROXY_PUBLIC_HOST
    if host_value == "auto":
        forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
        host_value = forwarded_host or request.url.hostname or "127.0.0.1"
        host_value = host_value.split(":")[0]
    return {
        "proxy_public_host": host_value,
        "proxy_public_http_port": PROXY_PUBLIC_HTTP_PORT,
        "proxy_public_socks_port": PROXY_PUBLIC_SOCKS_PORT,
    }


@app.get("/api/users", response_model=list[UserOut])
def list_users(_auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    users = db.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    return [
        UserOut(
            id=u.id,
            username=u.username,
            password=u.password,
            allow_http=u.allow_http,
            allow_socks5=u.allow_socks5,
            traffic_in_bytes=u.traffic_in_bytes,
            traffic_out_bytes=u.traffic_out_bytes,
            traffic_bytes=u.traffic_bytes,
            requests_count=u.requests_count,
            created_at=u.created_at,
        )
        for u in users
    ]


@app.post("/api/users", response_model=UserOut)
def create_user(payload: UserCreate, _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    validate_protocol_selection(payload.allow_http, payload.allow_socks5)
    existing = db.scalar(select(ProxyUser).where(ProxyUser.username == payload.username))
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    user = ProxyUser(
        username=payload.username,
        password=payload.password,
        allow_http=payload.allow_http,
        allow_socks5=payload.allow_socks5,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sync_proxy_config(db)
    return UserOut(
        id=user.id,
        username=user.username,
        password=user.password,
        allow_http=user.allow_http,
        allow_socks5=user.allow_socks5,
        traffic_in_bytes=user.traffic_in_bytes,
        traffic_out_bytes=user.traffic_out_bytes,
        traffic_bytes=user.traffic_bytes,
        requests_count=user.requests_count,
        created_at=user.created_at,
    )


@app.put("/api/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, payload: UserUpdate, _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    user = db.get(ProxyUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    new_http = payload.allow_http if payload.allow_http is not None else user.allow_http
    new_socks = payload.allow_socks5 if payload.allow_socks5 is not None else user.allow_socks5
    validate_protocol_selection(new_http, new_socks)

    if payload.password is not None:
        user.password = payload.password
    if payload.allow_http is not None:
        user.allow_http = payload.allow_http
    if payload.allow_socks5 is not None:
        user.allow_socks5 = payload.allow_socks5

    db.commit()
    db.refresh(user)
    sync_proxy_config(db)
    return UserOut(
        id=user.id,
        username=user.username,
        password=user.password,
        allow_http=user.allow_http,
        allow_socks5=user.allow_socks5,
        traffic_in_bytes=user.traffic_in_bytes,
        traffic_out_bytes=user.traffic_out_bytes,
        traffic_bytes=user.traffic_bytes,
        requests_count=user.requests_count,
        created_at=user.created_at,
    )


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    user = db.get(ProxyUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    sync_proxy_config(db)
    return {"status": "deleted"}


@app.post("/api/backup")
def backup_users(_auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    payload = dump_users(db)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    file_path = BACKUP_DIR / f"proxy-users-backup-{ts}.json"
    file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return FileResponse(path=str(file_path), media_type="application/json", filename=file_path.name)


@app.post("/api/restore")
async def restore_users(file: UploadFile = File(...), _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    data = await file.read()
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {exc}") from exc

    if not isinstance(payload, dict) or "users" not in payload or not isinstance(payload["users"], list):
        raise HTTPException(status_code=400, detail="Backup format is invalid")

    db.query(ProxyUser).delete()
    for item in payload["users"]:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username", "")).strip()
        password = str(item.get("password", ""))
        allow_http = bool(item.get("allow_http", False))
        allow_socks5 = bool(item.get("allow_socks5", False))
        if not username or ":" in username or "|" in username or " " in username:
            continue
        if ":" in password or "|" in password:
            continue
        if not allow_http and not allow_socks5:
            continue
        user = ProxyUser(
            username=username,
            password=password,
            allow_http=allow_http,
            allow_socks5=allow_socks5,
            traffic_in_bytes=int(item.get("traffic_in_bytes", 0)),
            traffic_out_bytes=int(item.get("traffic_out_bytes", 0)),
            traffic_bytes=int(item.get("traffic_bytes", 0)),
            requests_count=int(item.get("requests_count", 0)),
            created_at=datetime.fromisoformat(item.get("created_at")) if item.get("created_at") else datetime.now(timezone.utc),
        )
        db.add(user)
    db.commit()
    sync_proxy_config(db)
    return {"status": "restored"}
