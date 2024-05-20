"""Tests for qualicharge.auth.oidc module."""

from datetime import datetime

import httpx
import pytest
from fastapi.security import HTTPAuthorizationCredentials, SecurityScopes
from jose import jwt

from qualicharge.auth.factories import IDTokenFactory
from qualicharge.auth.oidc import discover_provider, get_public_keys, get_token
from qualicharge.conf import settings
from qualicharge.exceptions import OIDCAuthenticationError, OIDCProviderException


def setup_function():
    """Inactivate auth-specific LRU cache."""
    discover_provider.cache_clear()
    get_public_keys.cache_clear()


def test_discover_provider(httpx_mock):
    """Test the OIDC discover provider utility."""
    httpx_mock.add_response(
        method="GET",
        url="http://oidc/config",
        json={"jwks_uri": "https://oidc/certs"},
    )

    assert discover_provider("http://oidc/config") == {"jwks_uri": "https://oidc/certs"}


def test_discover_provider_with_bad_configuration(httpx_mock):
    """Test the OIDC discover provider utility with a bad configuration."""
    httpx_mock.add_exception(httpx.RequestError("Not found!"))

    with pytest.raises(
        OIDCProviderException,
        match="Unable to discover the OIDC provider configuration",
    ):
        discover_provider("http://oidc/wrong")


def test_get_public_keys(httpx_mock):
    """Test the OIDC get public keys utility."""
    httpx_mock.add_response(
        method="GET",
        url="http://oidc/certs",
        json=[{"kid": "1"}, {"kid": "2"}],
    )

    assert get_public_keys("http://oidc/certs") == [{"kid": "1"}, {"kid": "2"}]


def test__get_public_keys_with_bad_configuration(httpx_mock):
    """Test the OIDC get public keys utility with a bad configuration."""
    httpx_mock.add_exception(httpx.RequestError("Not found!"))

    with pytest.raises(
        OIDCProviderException,
        match="Unable to retrieve OIDC server signing public keys",
    ):
        get_public_keys("http://oidc/wrong")


def test_get_token(httpx_mock, monkeypatch, id_token_factory: IDTokenFactory):
    """Test the OIDC get token utility."""
    monkeypatch.setenv("QUALICHARGE_OIDC_PROVIDER_BASE_URL", "http://oidc")
    httpx_mock.add_response(
        method="GET",
        url=str(settings.OIDC_CONFIGURATION_URL),
        json={
            "jwks_uri": "https://oidc/certs",
            "id_token_signing_alg_values_supported": "HS256",
        },
    )
    httpx_mock.add_response(
        method="GET",
        url="https://oidc/certs",
        json=[
            "secret",
        ],
    )

    bearer_token = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=jwt.encode(
            claims=id_token_factory.build().model_dump(), key="secret"
        ),
    )
    token = get_token(security_scopes=SecurityScopes(), token=bearer_token)
    assert token.email == "john@doe.com"


def test_get_token_with_expired_token(
    httpx_mock, monkeypatch, id_token_factory: IDTokenFactory
):
    """Test the OIDC get token utility when the token expired."""
    monkeypatch.setenv("QUALICHARGE_OIDC_PROVIDER_BASE_URL", "http://oidc")
    httpx_mock.add_response(
        method="GET",
        url=str(settings.OIDC_CONFIGURATION_URL),
        json={
            "jwks_uri": "https://oidc/certs",
            "id_token_signing_alg_values_supported": "HS256",
        },
    )
    httpx_mock.add_response(
        method="GET",
        url="https://oidc/certs",
        json=[
            "secret",
        ],
    )

    # As exp should be set to iat + 300, the token should be expired
    iat = int(datetime.now().timestamp()) - 500
    bearer_token = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=jwt.encode(
            claims=id_token_factory.build(iat=iat).model_dump(),
            key="secret",
        ),
    )
    with pytest.raises(OIDCAuthenticationError, match="Token signature expired"):
        get_token(security_scopes=SecurityScopes(), token=bearer_token)