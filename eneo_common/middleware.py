import logging
from django.http import JsonResponse

from eneo_common.settings import get_keycloak_config
from eneo_common.utils.keycloak import decode_token
from eneo_common.exceptions import KeycloakTokenError, KeycloakUnavailableError

logger = logging.getLogger("eneo_common")


class KeycloakMiddleware:
    """
    Middleware Django qui extrait et valide le token JWT Keycloak
    sur chaque requête entrante.

    - Si un token valide est présent : attache le payload à request.user_payload
    - Si le token est invalide : retourne 401 immédiatement
    - Si pas de token : request.user_payload = None (routes publiques)
    - Si Keycloak est indisponible : retourne 503

    À ajouter dans settings.py du projet :
        MIDDLEWARE = [
            ...
            "eneo_common.middleware.KeycloakMiddleware",
        ]

    Note : Ce middleware est optionnel. La validation via
    KeycloakAuthentication (DRF) est suffisante pour les API pures.
    Ce middleware est utile si tu veux accéder au payload en dehors
    des vues DRF, ou pour des logs centralisés.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.user_payload = None

        config = get_keycloak_config()
        prefix = config["TOKEN_PREFIX"]
        auth_header = request.headers.get(config["TOKEN_HEADER"], "")

        if not auth_header.startswith(f"{prefix} "):
            # Pas de token — on laisse passer (les vues protégées géreront le 401)
            return self.get_response(request)

        token = auth_header[len(prefix) + 1:]

        if not token:
            return self._error(401, "Token manquant après le préfixe Bearer.")

        try:
            payload = decode_token(token)
            request.user_payload = payload
            logger.debug(f"Token valide pour sub={payload.get('sub')}")

        except KeycloakTokenError as e:
            return self._error(401, str(e))

        except KeycloakUnavailableError:
            logger.error("Keycloak indisponible dans le middleware.")
            return self._error(
                503,
                "Service d'authentification temporairement indisponible.",
            )

        return self.get_response(request)

    @staticmethod
    def _error(status: int, message: str) -> JsonResponse:
        return JsonResponse(
            {"error": message, "status": status},
            status=status,
        )
