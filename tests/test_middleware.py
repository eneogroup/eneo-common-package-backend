import pytest
import json
from unittest.mock import MagicMock, patch

from eneo_common.middleware import KeycloakMiddleware
from eneo_common.exceptions import KeycloakTokenError, KeycloakUnavailableError
from tests.conftest import VALID_PAYLOAD


def _make_request(auth_header=None):
    request = MagicMock()
    request.headers = {}
    if auth_header:
        request.headers["Authorization"] = auth_header
    return request


def _get_response(request):
    response = MagicMock()
    response.status_code = 200
    return response


class TestKeycloakMiddleware:

    def setup_method(self):
        self.middleware = KeycloakMiddleware(_get_response)

    @patch("eneo_common.middleware.get_keycloak_config")
    @patch("eneo_common.middleware.decode_token")
    def test_token_valide_attache_payload(self, mock_decode, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        mock_decode.return_value = VALID_PAYLOAD
        request = _make_request("Bearer valid.token")

        self.middleware(request)

        assert request.user_payload == VALID_PAYLOAD

    @patch("eneo_common.middleware.get_keycloak_config")
    def test_sans_token_user_payload_est_none(self, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        request = _make_request()
        self.middleware(request)
        assert request.user_payload is None

    @patch("eneo_common.middleware.get_keycloak_config")
    @patch("eneo_common.middleware.decode_token")
    def test_token_invalide_retourne_401(self, mock_decode, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        mock_decode.side_effect = KeycloakTokenError("Token invalide.")
        request = _make_request("Bearer bad.token")

        response = self.middleware(request)

        assert response.status_code == 401
        content = json.loads(response.content)
        assert content["status"] == 401

    @patch("eneo_common.middleware.get_keycloak_config")
    @patch("eneo_common.middleware.decode_token")
    def test_keycloak_indisponible_retourne_503(self, mock_decode, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        mock_decode.side_effect = KeycloakUnavailableError("Timeout.")
        request = _make_request("Bearer some.token")

        response = self.middleware(request)

        assert response.status_code == 503
