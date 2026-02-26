from django.conf import settings


DEFAULTS = {
    "SERVER_URL": "",
    "REALM": "",
    "CLIENT_ID": "",
    "CLIENT_SECRET": "",
    "VERIFY_SSL": True,
    "DECODE_ALGORITHMS": ["RS256"],
    "JWKS_CACHE_TTL": 3600,  # 1 heure en secondes
    "TOKEN_HEADER": "Authorization",
    "TOKEN_PREFIX": "Bearer",
}


def get_keycloak_config() -> dict:
    """
    Retourne la configuration Keycloak fusionnée avec les defaults.
    À appeler depuis django.conf.settings.KEYCLOAK_CONFIG.

    Exemple dans settings.py du projet :
        KEYCLOAK_CONFIG = {
            "SERVER_URL": env("KEYCLOAK_URL"),
            "REALM": env("KEYCLOAK_REALM"),
            "CLIENT_ID": env("KEYCLOAK_CLIENT_ID"),
            "CLIENT_SECRET": env("KEYCLOAK_CLIENT_SECRET"),
        }
    """
    user_config = getattr(settings, "KEYCLOAK_CONFIG", {})
    return {**DEFAULTS, **user_config}
