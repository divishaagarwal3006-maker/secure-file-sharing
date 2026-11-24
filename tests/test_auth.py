import pytest
from app import create_app
from db import init_db, get_db

PW = "Str0ng!Pass123"


@pytest.fixture
def client(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.db")})
    with app.app_context():
        init_db()
    return app.test_client()


def reg(c, u="alice", p=PW):
    return c.post("/register", data={"username": u, "password": p})


def test_register_and_login(client):
    reg(client)
    r = client.post("/login", data={"username": "alice", "password": PW})
    assert r.status_code == 302


def test_password_is_hashed(client):
    reg(client)
    with client.application.app_context():
        h = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert h.startswith("$argon2") and PW not in h


def test_weak_password_rejected(client):
    assert reg(client, p="short").status_code == 400


def test_wrong_password_is_generic(client):
    reg(client)
    r1 = client.post("/login", data={"username": "alice", "password": "wrong"})
    r2 = client.post("/login", data={"username": "nobody", "password": "wrong"})
    assert r1.status_code == 401 and r1.data == r2.data


def test_lockout_after_5_failures(client):
    reg(client)
    for _ in range(5):
        client.post("/login", data={"username": "alice", "password": "bad"})
    r = client.post("/login", data={"username": "alice", "password": PW})
    assert r.status_code == 429


def test_logout_clears_session(client):
    reg(client)
    client.post("/login", data={"username": "alice", "password": PW})
    client.post("/logout")
    with client.session_transaction() as s:
        assert "user_id" not in s


def test_protected_page_redirects(client):
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]