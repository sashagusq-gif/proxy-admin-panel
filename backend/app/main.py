import json
import os
import threading
import hmac
import hashlib
import base64
import secrets
import urllib.request
import ipaddress
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
MTPROTO_CONFIG_PATH = Path(os.environ.get("MTPROTO_CONFIG_PATH", "/opt/mtproto/config.toml"))
BACKUP_DIR = Path("/data/backups")
PANEL_SECRET_KEY = os.environ.get("PANEL_SECRET_KEY", "change-me-in-production")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
PROXY_PUBLIC_HOST = os.environ.get("PROXY_PUBLIC_HOST", "auto")
MTPROTO_PUBLIC_HOST = os.environ.get("MTPROTO_PUBLIC_HOST", "").strip()
PROXY_PUBLIC_SOCKS_PORT = int(os.environ.get("PROXY_PUBLIC_SOCKS_PORT", "11080"))
PROXY_PUBLIC_HTTP_PORT = int(os.environ.get("PROXY_PUBLIC_HTTP_PORT", "13128"))
PROXY_LOGDUMP_BYTES = int(os.environ.get("PROXY_LOGDUMP_BYTES", "65536"))
TRAFFIC_POLL_INTERVAL_SECONDS = float(os.environ.get("TRAFFIC_POLL_INTERVAL_SECONDS", "2.0"))
MTPROTO_INTERNAL_PORT = int(os.environ.get("MTPROTO_INTERNAL_PORT", "3443"))
MTPROTO_PUBLIC_PORT = int(os.environ.get("MTPROTO_PUBLIC_PORT", "2053"))
MTPROTO_FAKE_TLS_DOMAIN = os.environ.get("MTPROTO_FAKE_TLS_DOMAIN", "yandex.ru")
MTPROTO_SECRET_MODE = os.environ.get("MTPROTO_SECRET_MODE", "faketls").strip().lower()
MTPROTO_STATS_URL = os.environ.get("MTPROTO_STATS_URL", "http://mtproto:9090/stats")
TRAFFIC_SAMPLING_INTERVAL_SECONDS = int(os.environ.get("TRAFFIC_SAMPLING_INTERVAL_SECONDS", "30"))
SESSION_COOKIE_NAME = "panel_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
_public_ip_cache: str | None = None


class Base(DeclarativeBase):
    pass


class ProxyUser(Base):
    __tablename__ = "proxy_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(128))
    allow_http: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_socks5: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_mtproto: Mapped[bool] = mapped_column(Boolean, default=False)
    mtproto_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)
    traffic_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_bytes: Mapped[int] = mapped_column(Integer, default=0)
    requests_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class TrafficState(Base):
    __tablename__ = "traffic_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    file_offset: Mapped[int] = mapped_column(Integer, default=0)
    last_sample_ts: Mapped[int] = mapped_column(Integer, default=0)


class MTProtoUserState(Base):
    __tablename__ = "mtproto_user_state"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    last_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    last_connections: Mapped[int] = mapped_column(Integer, default=0)


class TrafficSample(Base):
    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    traffic_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_bytes: Mapped[int] = mapped_column(Integer, default=0)


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

templates = Jinja2Templates(directory="/app/templates")


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=3, max_length=128)
    allow_http: bool = True
    allow_socks5: bool = True
    allow_mtproto: bool = False

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
    allow_mtproto: bool | None = None
    regenerate_mtproto_secret: bool = False

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
    allow_mtproto: bool
    mtproto_secret: str | None
    traffic_in_bytes: int
    traffic_out_bytes: int
    traffic_bytes: int
    requests_count: int
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class TrafficSeriesPoint(BaseModel):
    captured_at: datetime
    traffic_in_bytes: int
    traffic_out_bytes: int
    traffic_bytes: int


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(proxy_users)")).fetchall()]
        if "traffic_in_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_in_bytes INTEGER DEFAULT 0"))
        if "traffic_out_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_out_bytes INTEGER DEFAULT 0"))
        if "allow_mtproto" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN allow_mtproto BOOLEAN DEFAULT 0"))
        if "mtproto_secret" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN mtproto_secret TEXT"))
        conn.execute(
            text(
                "UPDATE proxy_users "
                "SET traffic_out_bytes = traffic_bytes "
                "WHERE traffic_bytes > 0 AND traffic_in_bytes = 0 AND traffic_out_bytes = 0"
            )
        )
        traffic_state_columns = [row[1] for row in conn.execute(text("PRAGMA table_info(traffic_state)")).fetchall()]
        if "last_sample_ts" not in traffic_state_columns:
            conn.execute(text("ALTER TABLE traffic_state ADD COLUMN last_sample_ts INTEGER DEFAULT 0"))
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


def generate_mtproto_secret() -> str:
    # mtg-multi accepts Telegram transport secrets:
    # - classic secure mode: dd + 16 random bytes (34 hex chars total)
    # - faketls mode: ee + 16 random bytes + domain bytes (hex)
    if MTPROTO_SECRET_MODE == "faketls":
        random_part = secrets.token_hex(16)
        fake_tls_hex = MTPROTO_FAKE_TLS_DOMAIN.encode("utf-8").hex()
        return f"ee{random_part}{fake_tls_hex}"
    return f"dd{secrets.token_hex(16)}"


def sanitize_mtproto_secret(raw_secret: str | None) -> str:
    secret = (raw_secret or "").strip().lower()
    if not secret:
        return generate_mtproto_secret()
    is_hex = all(ch in "0123456789abcdef" for ch in secret)
    if MTPROTO_SECRET_MODE == "classic":
        # Backward-compat: upgrade old 32-hex secret to secure dd-prefixed format.
        if len(secret) == 32 and is_hex:
            return f"dd{secret}"
        if len(secret) == 34 and secret.startswith("dd") and is_hex:
            return secret
        return generate_mtproto_secret()
    if MTPROTO_SECRET_MODE == "faketls":
        fake_tls_hex = MTPROTO_FAKE_TLS_DOMAIN.encode("utf-8").hex()
        if secret.startswith("ee") and secret.endswith(fake_tls_hex) and is_hex and len(secret) > 34:
            return secret
        return generate_mtproto_secret()
    return generate_mtproto_secret()


def render_mtproto_config(users: list[ProxyUser]) -> str:
    enabled_users = [(u.username, str(u.mtproto_secret)) for u in users if u.allow_mtproto and u.mtproto_secret]
    if not enabled_users:
        # Keep proxy up with one synthetic secret to avoid service crash.
        enabled_users = [("disabled_user", generate_mtproto_secret())]
    lines = [
        f'bind-to = "0.0.0.0:{MTPROTO_INTERNAL_PORT}"',
        'api-bind-to = "0.0.0.0:9090"',
        "",
        "[throttle]",
        "max-connections = 5000",
        "",
        "[secrets]",
    ]
    for username, secret in enabled_users:
        lines.append(f'"{username}" = "{secret}"')
    return "\n".join(lines) + "\n"


def sync_mtproto_config(session: Session) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    content = render_mtproto_config(users)
    MTPROTO_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = MTPROTO_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(MTPROTO_CONFIG_PATH)


def normalize_mtproto_secrets(session: Session) -> None:
    users = session.scalars(select(ProxyUser).where(ProxyUser.allow_mtproto == True)).all()
    changed = False
    for user in users:
        normalized = sanitize_mtproto_secret(user.mtproto_secret)
        if user.mtproto_secret != normalized:
            user.mtproto_secret = normalized
            changed = True
    if changed:
        session.commit()


def sync_proxy_config(session: Session) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    content = render_proxy_config(users)
    PROXY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = PROXY_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(PROXY_CONFIG_PATH)


def poll_mtproto_stats(session: Session) -> None:
    try:
        with urllib.request.urlopen(MTPROTO_STATS_URL, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return
    users_payload = payload.get("users")
    if not isinstance(users_payload, dict):
        return

    db_users = session.scalars(select(ProxyUser).where(ProxyUser.username.in_(list(users_payload.keys())))).all()
    by_username = {u.username: u for u in db_users}
    for username, stat in users_payload.items():
        if username not in by_username or not isinstance(stat, dict):
            continue
        user = by_username[username]
        if not user.allow_mtproto:
            continue
        in_total = int(stat.get("bytes_in", 0))
        out_total = int(stat.get("bytes_out", 0))
        connections_total = int(stat.get("connections", 0))

        state = session.get(MTProtoUserState, username)
        if state is None:
            state = MTProtoUserState(
                username=username,
                last_in_bytes=in_total,
                last_out_bytes=out_total,
                last_connections=connections_total,
            )
            session.add(state)
            continue

        delta_in = max(0, in_total - state.last_in_bytes)
        delta_out = max(0, out_total - state.last_out_bytes)
        delta_conn = max(0, connections_total - state.last_connections)
        if delta_in or delta_out or delta_conn:
            user.traffic_in_bytes += delta_in
            user.traffic_out_bytes += delta_out
            user.traffic_bytes += delta_in + delta_out
            user.requests_count += delta_conn

        state.last_in_bytes = in_total
        state.last_out_bytes = out_total
        state.last_connections = connections_total


def sample_traffic(session: Session, now: datetime) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    total_in = 0
    total_out = 0
    total_all = 0
    for user in users:
        total_in += user.traffic_in_bytes
        total_out += user.traffic_out_bytes
        total_all += user.traffic_bytes
        session.add(
            TrafficSample(
                user_id=user.id,
                captured_at=now,
                traffic_in_bytes=user.traffic_in_bytes,
                traffic_out_bytes=user.traffic_out_bytes,
                traffic_bytes=user.traffic_bytes,
            )
        )
    session.add(
        TrafficSample(
            user_id=None,
            captured_at=now,
            traffic_in_bytes=total_in,
            traffic_out_bytes=total_out,
            traffic_bytes=total_all,
        )
    )


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

                    poll_mtproto_stats(session)

                    now_ts = int(datetime.now(timezone.utc).timestamp())
                    if state.last_sample_ts == 0 or now_ts - state.last_sample_ts >= TRAFFIC_SAMPLING_INTERVAL_SECONDS:
                        sample_traffic(session, datetime.now(timezone.utc))
                        state.last_sample_ts = now_ts

                    session.commit()
        except Exception:
            # Worker must survive temporary file/db errors.
            pass
        stop_event.wait(TRAFFIC_POLL_INTERVAL_SECONDS)


def validate_protocol_selection(allow_http: bool, allow_socks5: bool) -> None:
    if not allow_http and not allow_socks5:
        raise HTTPException(status_code=400, detail="At least one protocol must be enabled")


def validate_protocol_selection_extended(allow_http: bool, allow_socks5: bool, allow_mtproto: bool) -> None:
    if not allow_http and not allow_socks5 and not allow_mtproto:
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


def detect_public_ip() -> str | None:
    global _public_ip_cache
    if _public_ip_cache:
        return _public_ip_cache
    urls = ("https://api.ipify.org", "https://ifconfig.me/ip")
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                value = response.read().decode("utf-8").strip()
            ipaddress.ip_address(value)
            _public_ip_cache = value
            return value
        except Exception:
            continue
    return None


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
                "allow_mtproto": user.allow_mtproto,
                "mtproto_secret": user.mtproto_secret,
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
        normalize_mtproto_secrets(session)
        sync_proxy_config(session)
        sync_mtproto_config(session)
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
    mtproto_host = MTPROTO_PUBLIC_HOST or detect_public_ip() or host_value
    return {
        "proxy_public_host": host_value,
        "proxy_public_mtproto_host": mtproto_host,
        "proxy_public_http_port": PROXY_PUBLIC_HTTP_PORT,
        "proxy_public_socks_port": PROXY_PUBLIC_SOCKS_PORT,
        "proxy_public_mtproto_port": MTPROTO_PUBLIC_PORT,
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
            allow_mtproto=u.allow_mtproto,
            mtproto_secret=u.mtproto_secret,
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
    validate_protocol_selection_extended(payload.allow_http, payload.allow_socks5, payload.allow_mtproto)
    existing = db.scalar(select(ProxyUser).where(ProxyUser.username == payload.username))
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    user = ProxyUser(
        username=payload.username,
        password=payload.password,
        allow_http=payload.allow_http,
        allow_socks5=payload.allow_socks5,
        allow_mtproto=payload.allow_mtproto,
        mtproto_secret=generate_mtproto_secret() if payload.allow_mtproto else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sync_proxy_config(db)
    sync_mtproto_config(db)
    return UserOut(
        id=user.id,
        username=user.username,
        password=user.password,
        allow_http=user.allow_http,
        allow_socks5=user.allow_socks5,
        allow_mtproto=user.allow_mtproto,
        mtproto_secret=user.mtproto_secret,
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
    new_mtproto = payload.allow_mtproto if payload.allow_mtproto is not None else user.allow_mtproto
    validate_protocol_selection_extended(new_http, new_socks, new_mtproto)

    if payload.password is not None:
        user.password = payload.password
    if payload.allow_http is not None:
        user.allow_http = payload.allow_http
    if payload.allow_socks5 is not None:
        user.allow_socks5 = payload.allow_socks5
    if payload.allow_mtproto is not None:
        user.allow_mtproto = payload.allow_mtproto
        if user.allow_mtproto:
            user.mtproto_secret = sanitize_mtproto_secret(user.mtproto_secret)
    if payload.regenerate_mtproto_secret:
        user.mtproto_secret = generate_mtproto_secret()

    db.commit()
    db.refresh(user)
    sync_proxy_config(db)
    sync_mtproto_config(db)
    return UserOut(
        id=user.id,
        username=user.username,
        password=user.password,
        allow_http=user.allow_http,
        allow_socks5=user.allow_socks5,
        allow_mtproto=user.allow_mtproto,
        mtproto_secret=user.mtproto_secret,
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
    sync_mtproto_config(db)
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
        allow_mtproto = bool(item.get("allow_mtproto", False))
        if not username or ":" in username or "|" in username or " " in username:
            continue
        if ":" in password or "|" in password:
            continue
        if not allow_http and not allow_socks5 and not allow_mtproto:
            continue
        user = ProxyUser(
            username=username,
            password=password,
            allow_http=allow_http,
            allow_socks5=allow_socks5,
            allow_mtproto=allow_mtproto,
            mtproto_secret=sanitize_mtproto_secret(str(item.get("mtproto_secret") or "")) if allow_mtproto else None,
            traffic_in_bytes=int(item.get("traffic_in_bytes", 0)),
            traffic_out_bytes=int(item.get("traffic_out_bytes", 0)),
            traffic_bytes=int(item.get("traffic_bytes", 0)),
            requests_count=int(item.get("requests_count", 0)),
            created_at=datetime.fromisoformat(item.get("created_at")) if item.get("created_at") else datetime.now(timezone.utc),
        )
        db.add(user)
    db.commit()
    sync_proxy_config(db)
    sync_mtproto_config(db)
    return {"status": "restored"}


@app.get("/api/traffic/samples", response_model=list[TrafficSeriesPoint])
def traffic_samples(
    user_id: int | None = None,
    minutes: int = 180,
    _auth: str = Depends(require_auth),
    db: Session = Depends(get_db),
):
    minutes = max(10, min(minutes, 24 * 60))
    threshold = datetime.now(timezone.utc).timestamp() - minutes * 60
    threshold_dt = datetime.fromtimestamp(threshold, timezone.utc)
    if user_id is None:
        rows = db.scalars(
            select(TrafficSample)
            .where(TrafficSample.user_id.is_(None), TrafficSample.captured_at >= threshold_dt)
            .order_by(TrafficSample.captured_at.asc())
        ).all()
    else:
        rows = db.scalars(
            select(TrafficSample)
            .where(TrafficSample.user_id == user_id, TrafficSample.captured_at >= threshold_dt)
            .order_by(TrafficSample.captured_at.asc())
        ).all()
    return [
        TrafficSeriesPoint(
            captured_at=row.captured_at,
            traffic_in_bytes=row.traffic_in_bytes,
            traffic_out_bytes=row.traffic_out_bytes,
            traffic_bytes=row.traffic_bytes,
        )
        for row in rows
    ]
