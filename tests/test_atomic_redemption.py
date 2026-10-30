"""Single-use credentials stay single-use under concurrency: codes, refresh tokens (with family revoke), and the e-mail unique index."""
import threading

import psycopg
import pytest
from conftest import BASE, authorize, code_from, exchange, login_sso, make_world, pkce
from fastapi.testclient import TestClient

THREADS = 8


def race(idp, fn):
    """Run fn(client) in THREADS threads released together; each thread has its own client (cookie jar and connection)."""
    barrier, results = threading.Barrier(THREADS), []

    def run():
        client = TestClient(idp.app, base_url=BASE)
        barrier.wait()
        results.append(fn(client))

    ts = [threading.Thread(target=run) for _ in range(THREADS)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return results


def test_one_authorization_code_redeems_exactly_once_concurrently(idp):
    w = make_world(idp)
    browser = login_sso(idp)
    for _ in range(3):
        pk = pkce()
        code, _ = code_from(authorize(browser, pk, scope="openid offline_access"))
        out = race(idp, lambda c, code=code, pk=pk: exchange(c, code, pk[0], w["secret"]).status_code)
        assert sorted(out) == [200] + [400] * (THREADS - 1), out


def test_one_refresh_token_rotates_exactly_once_and_reuse_kills_the_family(idp):
    w = make_world(idp)
    pk = pkce()
    code, _ = code_from(authorize(login_sso(idp), pk, scope="openid offline_access"))
    first = exchange(idp, code, pk[0], w["secret"]).json()["refresh_token"]

    def refresh(c):
        return c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first}, auth=("demo", w["secret"]))

    out = race(idp, refresh)
    assert sorted(r.status_code for r in out) == [200] + [400] * (THREADS - 1), [r.status_code for r in out]
    winner = next(r for r in out if r.status_code == 200).json()["refresh_token"]
    # the double redemption is treated as reuse: even the token the winner received is dead now
    assert refresh(idp).status_code == 400
    assert idp.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": winner}, auth=("demo", w["secret"])).status_code == 400
    from identity import core
    with core.db.connect() as c:
        assert c.execute("SELECT count(*) AS n FROM oauth_refresh WHERE revoked_at IS NULL").fetchone()["n"] == 0


def test_idp_user_email_is_unique_ignoring_case(idp):
    make_world(idp)
    from identity import core
    with core.db.connect() as c:
        with pytest.raises(psycopg.errors.UniqueViolation):
            c.execute("INSERT INTO idp_user (id, username, email) VALUES ('usr_abcdefghijkl', 'ada2', 'ADA@Example.org')")
        c.rollback()
