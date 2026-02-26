import time
import logging
import requests
from jose import jwt, JWTError, ExpiredSignatureError
from threading import Lock

from eneo_common.settings import get_keycloak_config
from eneo_common.exceptions import (
    KeycloakUnavailableError,
    KeycloakTokenError,
    KeycloakConfigError,
)

logger = logging.getLogger("eneo_common")


class JWKSCache:
    """
    Cache thread-safe des clés publiques JWKS de Keycloak.
    Évite un appel réseau à chaque requête API.
    TTL configurable via KEYCLOAK_CONFIG["JWKS_CACHE_TTL"].
    """

    def __init__(self):
        self._cache: dict | None = None
        self._fetched_at: float = 0
        self._lock = Lock()

    def _is_expired(self) -> bool:
        config = get_keycloak_config()
        ttl = config.get("JWKS_CACHE_TTL", 3600)
        return (time.time() - self._fetched_at) > ttl

    def _fetch(self) -> dict:
        config = get_keycloak_config()

        if not config.get("SERVER_URL") or not config.get("REALM"):
            raise KeycloakConfigError(
                "KEYCLOAK_CONFIG manquant : SERVER_URL et REALM sont requis."
            )

        url = (
            f"{config['SERVER_URL']}/realms/{config['REALM']}"
            f"/protocol/openid-connect/certs"
        )

        try:
            response = requests.get(url, verify=config["VERIFY_SSL"], timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            raise KeycloakUnavailableError(
                f"Impossible de joindre Keycloak à {url}. "
                "Vérifiez que le serveur est en ligne."
            )
        except requests.exceptions.Timeout:
            raise KeycloakUnavailableError(
                "Keycloak n'a pas répondu dans les délais (timeout 5s)."
            )
        except requests.exceptions.HTTPError as e:
            raise KeycloakUnavailableError(
                f"Keycloak a retourné une erreur HTTP : {e}"
            )

    def get(self) -> dict:
        """
        Retourne les clés JWKS depuis le cache ou les re-fetche si expiré.
        Thread-safe.
        """
        with self._lock:
            if self._cache is None or self._is_expired():
                logger.debug("Cache JWKS expiré ou vide, re-fetch depuis Keycloak.")
                self._cache = self._fetch()
                self._fetched_at = time.time()
            return self._cache

    def invalidate(self):
        """Force le re-fetch au prochain appel (utile en test)."""
        with self._lock:
            self._cache = None
            self._fetched_at = 0


# Instance singleton partagée dans tout le process
jwks_cache = JWKSCache()


def decode_token(token: str) -> dict:
    """
    Valide et décode un token JWT Keycloak.

    Vérifie :
    - La signature via JWKS
    - L'expiration
    - L'audience (CLIENT_ID)
    - L'algorithme (RS256 par défaut)

    Retourne le payload décodé ou lève une exception.

    Raises:
        KeycloakTokenError: Token invalide, expiré ou mal formé.
        KeycloakUnavailableError: Impossible de récupérer les clés JWKS.
        KeycloakConfigError: Configuration manquante.
    """
    config = get_keycloak_config()
    jwks = jwks_cache.get()

    try:
        payload = jwt.decode(
            token,
            jwks,
            algorithms=config["DECODE_ALGORITHMS"],
            audience=config["CLIENT_ID"],
        )
        return payload

    except ExpiredSignatureError:
        raise KeycloakTokenError("Token expiré. Veuillez vous reconnecter.")

    except JWTError as e:
        # Si ça échoue à cause d'une clé obsolète, on invalide le cache et on retente
        logger.warning(f"Échec décodage JWT ({e}), tentative avec clés fraîches.")
        jwks_cache.invalidate()
        fresh_jwks = jwks_cache.get()

        try:
            payload = jwt.decode(
                token,
                fresh_jwks,
                algorithms=config["DECODE_ALGORITHMS"],
                audience=config["CLIENT_ID"],
            )
            return payload
        except JWTError as retry_error:
            raise KeycloakTokenError(f"Token invalide : {retry_error}")


def extract_realm_roles(payload: dict) -> list[str]:
    """Extrait les rôles realm depuis le payload JWT."""
    return payload.get("realm_access", {}).get("roles", [])


def extract_client_roles(payload: dict, client_id: str) -> list[str]:
    """Extrait les rôles d'un client spécifique depuis le payload JWT."""
    return payload.get("resource_access", {}).get(client_id, {}).get("roles", [])
