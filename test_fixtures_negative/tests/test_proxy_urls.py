import pytest

PROXIES = {"http": "http://user:pass@proxy.internal.corp:3128"}


@pytest.mark.parametrize(
    "url, auth",
    [
        ("http://user:pass%23pass@complex.url.com/path?query=yes", ("user", "pass#pass")),
        ("http://user:pass%20pass@complex.url.com/path?query=yes", ("user", "pass pass")),
        ("http://user:password@complex.url.com/path", ("user", "password")),
    ],
)
def test_get_auth_from_url(url, auth):
    assert get_auth_from_url(url) == auth


def test_login(client):
    login(client, "admin", "password")
    login(client, "admin", "secret")
