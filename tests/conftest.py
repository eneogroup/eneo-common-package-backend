import pytest
import time
from unittest.mock import patch, MagicMock


# ------------------------------------------------------------------ #
#  Payload JWT de référence (structure réelle Keycloak Eneo Group)   #
# ------------------------------------------------------------------ #

VALID_PAYLOAD = {
    "sub": "550e8400-e29b-41d4-a716-446655440000",
    "email": "john.doe@eneogroup.com",
    "given_name": "John",
    "family_name": "Doe",
    "preferred_username": "john.doe@eneogroup.com",
    "realm_access": {
        "roles": ["user", "staff"]
    },
    "resource_access": {
        "eneo-backend": {
            "roles": ["zury:read", "zury:write"]
        }
    },
    "exp": int(time.time()) + 3600,
    "iat": int(time.time()),
    "aud": "eneo-backend",
}

ADMIN_PAYLOAD = {
    **VALID_PAYLOAD,
    "sub": "660e8400-e29b-41d4-a716-446655440001",
    "email": "admin@eneogroup.com",
    "preferred_username": "admin@eneogroup.com",
    "realm_access": {
        "roles": ["user", "staff", "eneo-admin"]
    },
}

EXPIRED_PAYLOAD = {
    **VALID_PAYLOAD,
    "exp": int(time.time()) - 100,  # Expiré il y a 100 secondes
}


@pytest.fixture
def valid_payload():
    return VALID_PAYLOAD.copy()


@pytest.fixture
def admin_payload():
    return ADMIN_PAYLOAD.copy()


@pytest.fixture
def expired_payload():
    return EXPIRED_PAYLOAD.copy()


@pytest.fixture
def mock_decode_token_valid(valid_payload):
    """Mock decode_token pour retourner un payload valide."""
    with patch("eneo_common.authentication.decode_token", return_value=valid_payload):
        yield valid_payload


@pytest.fixture
def mock_decode_token_admin(admin_payload):
    """Mock decode_token pour retourner un payload admin."""
    with patch("eneo_common.authentication.decode_token", return_value=admin_payload):
        yield admin_payload


@pytest.fixture
def mock_django_settings():
    """Configure les settings Django minimaux pour les tests."""
    with patch("eneo_common.settings.settings") as mock_settings:
        mock_settings.KEYCLOAK_CONFIG = {
            "SERVER_URL": "https://sso.eneogroup.com",
            "REALM": "eneogroup-si",
            "CLIENT_ID": "eneo-backend",
            "CLIENT_SECRET": "test-secret",
            "VERIFY_SSL": False,
            "DECODE_ALGORITHMS": ["RS256"],
            "JWKS_CACHE_TTL": 3600,
            "TOKEN_HEADER": "Authorization",
            "TOKEN_PREFIX": "Bearer",
        }
        yield mock_settings
