import pytest
from unittest.mock import patch, MagicMock
from rest_framework.exceptions import AuthenticationFailed

from eneo_common.authentication import KeycloakAuthentication, KeycloakUser
from eneo_common.exceptions import KeycloakTokenError, KeycloakUnavailableError
from tests.conftest import VALID_PAYLOAD, ADMIN_PAYLOAD


# ------------------------------------------------------------------ #
#  KeycloakUser                                                       #
# ------------------------------------------------------------------ #

class TestKeycloakUser:

    def test_attributs_de_base(self):
        user = KeycloakUser(VALID_PAYLOAD)
        assert user.sub == "550e8400-e29b-41d4-a716-446655440000"
        assert user.email == "john.doe@eneogroup.com"
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.is_authenticated is True
        assert user.is_anonymous is False

    def test_pk_et_id_retournent_sub(self):
        user = KeycloakUser(VALID_PAYLOAD)
        assert user.pk == user.sub
        assert user.id == user.sub

    def test_realm_roles(self):
        user = KeycloakUser(VALID_PAYLOAD)
        assert "user" in user.realm_roles
        assert "staff" in user.realm_roles
        assert "eneo-admin" not in user.realm_roles

    def test_has_realm_role(self):
        user = KeycloakUser(VALID_PAYLOAD)
        assert user.has_realm_role("user") is True
        assert user.has_realm_role("eneo-admin") is False

    def test_has_client_role(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            user = KeycloakUser(VALID_PAYLOAD)
            assert user.has_client_role("zury:read") is True
            assert user.has_client_role("zury:write") is True
            assert user.has_client_role("zury:delete") is False

    def test_has_role_cherche_dans_realm_et_client(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            user = KeycloakUser(VALID_PAYLOAD)
            assert user.has_role("user") is True          # realm
            assert user.has_role("zury:read") is True     # client
            assert user.has_role("inexistant") is False

    def test_admin_has_perm(self):
        user = KeycloakUser(ADMIN_PAYLOAD)
        assert user.has_perm("any.perm") is True

    def test_non_admin_has_perm(self):
        user = KeycloakUser(VALID_PAYLOAD)
        assert user.has_perm("any.perm") is False

    def test_str(self):
        user = KeycloakUser(VALID_PAYLOAD)
        assert str(user) == "john.doe@eneogroup.com"


# ------------------------------------------------------------------ #
#  KeycloakAuthentication                                             #
# ------------------------------------------------------------------ #

class TestKeycloakAuthentication:

    def setup_method(self):
        self.auth = KeycloakAuthentication()

    def _make_request(self, auth_header=None):
        request = MagicMock()
        request.headers = {}
        if auth_header:
            request.headers["Authorization"] = auth_header
        return request

    @patch("eneo_common.authentication.get_keycloak_config")
    @patch("eneo_common.authentication.decode_token")
    def test_token_valide_retourne_user(self, mock_decode, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
            "CLIENT_ID": "eneo-backend",
        }
        mock_decode.return_value = VALID_PAYLOAD
        request = self._make_request("Bearer valid.jwt.token")

        result = self.auth.authenticate(request)

        assert result is not None
        user, token = result
        assert isinstance(user, KeycloakUser)
        assert user.sub == VALID_PAYLOAD["sub"]
        assert token == "valid.jwt.token"

    @patch("eneo_common.authentication.get_keycloak_config")
    def test_sans_header_retourne_none(self, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        request = self._make_request()
        result = self.auth.authenticate(request)
        assert result is None

    @patch("eneo_common.authentication.get_keycloak_config")
    @patch("eneo_common.authentication.decode_token")
    def test_token_expire_leve_401(self, mock_decode, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        mock_decode.side_effect = KeycloakTokenError("Token expiré.")
        request = self._make_request("Bearer expired.token")

        with pytest.raises(AuthenticationFailed) as exc:
            self.auth.authenticate(request)
        assert "expiré" in str(exc.value).lower()

    @patch("eneo_common.authentication.get_keycloak_config")
    @patch("eneo_common.authentication.decode_token")
    def test_keycloak_indisponible_leve_503_message(self, mock_decode, mock_config):
        mock_config.return_value = {
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        mock_decode.side_effect = KeycloakUnavailableError("Connexion refusée.")
        request = self._make_request("Bearer some.token")

        with pytest.raises(AuthenticationFailed) as exc:
            self.auth.authenticate(request)
        assert "indisponible" in str(exc.value).lower()

    @patch("eneo_common.authentication.get_keycloak_config")
    def test_authenticate_header(self, mock_config):
        mock_config.return_value = {}
        request = MagicMock()
        result = self.auth.authenticate_header(request)
        assert result == 'Bearer realm="eneo-group"'
