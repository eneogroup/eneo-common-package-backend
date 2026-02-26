import pytest
from unittest.mock import MagicMock, patch

from eneo_common.authentication import KeycloakUser
from eneo_common.permissions import (
    IsKeycloakAuthenticated,
    IsEneoAdmin,
    IsStaff,
    IsZuryUser,
    CanReadZury,
    CanWriteZury,
    require_role,
    require_client_role,
)
from tests.conftest import VALID_PAYLOAD, ADMIN_PAYLOAD


def _make_request(payload=None, user=None):
    request = MagicMock()
    if user:
        request.user = user
    elif payload:
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request.user = KeycloakUser(payload)
    else:
        request.user = MagicMock(is_authenticated=False)
    return request


class TestIsKeycloakAuthenticated:

    def test_user_authentifie_autorise(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(VALID_PAYLOAD)
            perm = IsKeycloakAuthenticated()
            assert perm.has_permission(request, None) is True

    def test_user_non_keycloak_refuse(self):
        request = MagicMock()
        request.user = MagicMock(spec=[])  # Pas un KeycloakUser
        perm = IsKeycloakAuthenticated()
        assert perm.has_permission(request, None) is False


class TestIsEneoAdmin:

    def test_admin_autorise(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(ADMIN_PAYLOAD)
            perm = IsEneoAdmin()
            assert perm.has_permission(request, None) is True

    def test_non_admin_refuse(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(VALID_PAYLOAD)
            perm = IsEneoAdmin()
            assert perm.has_permission(request, None) is False


class TestIsZuryUser:

    def test_avec_role_zury_read_autorise(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(VALID_PAYLOAD)
            perm = IsZuryUser()
            assert perm.has_permission(request, None) is True

    def test_sans_role_zury_refuse(self):
        payload_sans_zury = {
            **VALID_PAYLOAD,
            "resource_access": {},
        }
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(payload_sans_zury)
            perm = IsZuryUser()
            assert perm.has_permission(request, None) is False


class TestRequireRole:

    def test_require_role_valide(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(VALID_PAYLOAD)
            perm = require_role("staff")()
            assert perm.has_permission(request, None) is True

    def test_require_role_invalide(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(VALID_PAYLOAD)
            perm = require_role("eneo-admin")()
            assert perm.has_permission(request, None) is False

    def test_require_role_nom_de_classe_dynamique(self):
        perm_class = require_role("nouveau-role")
        assert "nouveau_role" in perm_class.__name__

    def test_require_client_role(self):
        with patch("eneo_common.authentication.get_keycloak_config") as mock_config:
            mock_config.return_value = {"CLIENT_ID": "eneo-backend"}
            request = _make_request(VALID_PAYLOAD)
            perm = require_client_role("zury:write")()
            assert perm.has_permission(request, None) is True
