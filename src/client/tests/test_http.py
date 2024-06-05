"""Tests for the qcc.http module."""

import httpx
import pytest

from qcc.exceptions import AuthenticationError, ConfigurationError
from qcc.http import APIClient, OAuth2AccessToken

# ruff: noqa: S105, S106


def test_client_init(httpx_mock):
    """Test the APIClient instantiation."""
    httpx_mock.add_response(
        method="POST", json={"access_token": "foo", "token_type": "bearer"}
    )

    with pytest.raises(
        ConfigurationError, match="API credentials are not set in client nor settings"
    ):
        APIClient()

    client = APIClient(username="johndoe", password="fake")
    assert isinstance(client._auth, OAuth2AccessToken)
    assert client._auth.access_token == "foo"


def test_client_get_auth_with_invalid_api_response(httpx_mock):
    """Test the APIClient get_auth method when API response is not valid."""
    # response body is not a valid JSON
    httpx_mock.add_response(method="POST", text="Oops")

    with pytest.raises(
        AuthenticationError,
        match=("Invalid response from the API server with provided credentials"),
    ):
        APIClient(username="johndoe", password="fake")

    # token_type is missing in the response
    httpx_mock.add_response(method="POST", json={"access_token": "foo"})

    with pytest.raises(
        AuthenticationError,
        match=(
            "Cannot get an access token from the API server with provided credentials"
        ),
    ):
        APIClient(username="johndoe", password="fake")


@pytest.mark.anyio
async def test_client_unauthorized_request(httpx_mock):
    """Test client request when the API server returns a 401 status code."""
    httpx_mock.add_response(
        method="POST", json={"access_token": "foo", "token_type": "bearer"}
    )
    client = APIClient(username="johndoe", password="fake")

    httpx_mock.add_response(method="GET", status_code=401, text="Oops")
    response = await client.get("/auth/whoami")
    assert response.status_code == httpx.codes.UNAUTHORIZED
    # Response has not been modified
    assert response.content == b"Oops"


@pytest.mark.anyio
async def test_client_expired_token_renewal(httpx_mock):
    """Test client request when the access token expired."""
    httpx_mock.add_response(
        method="POST", json={"access_token": "foo", "token_type": "bearer"}
    )
    client = APIClient(username="johndoe", password="fake")

    httpx_mock.add_response(
        method="GET",
        status_code=401,
        json={"message": "Authentication failed: Token signature expired"},
    )
    httpx_mock.add_response(
        method="GET",
        status_code=200,
        json={"fake": 1},
    )
    response = await client.get("/auth/whoami")
    assert response.status_code == httpx.codes.OK
    assert response.content == b'{"fake": 1}'

    # Check requests
    requests = httpx_mock.get_requests()
    assert requests[0].method == "POST"  # first token
    assert requests[1].method == "GET"  # 401: token expired
    assert requests[2].method == "POST"  # second (new) token
    assert requests[3].method == "GET"  # 200: valid request
