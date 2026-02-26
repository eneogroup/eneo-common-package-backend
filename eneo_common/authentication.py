import logging
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from eneo_common.settings import get_keycloak_config
from eneo_common.utils.keycloak import (
    decode_token,
    extract_realm_roles,
    extract_client_roles,
)
from eneo_common.exceptions import (
    KeycloakTokenError,
    KeycloakUnavailableError,
    KeycloakConfigError,
)

logger = logging.getLogger("eneo_common")


class KeycloakUser:
    """
    Représente un utilisateur authentifié via Keycloak.
    Pas de base de données — construit uniquement depuis le payload JWT.

    Le sub est l'identifiant universel immuable. Il sert de clé étrangère
    dans tous les modèles Django des projets (Zury, Mosala, eneo-account...).
    """

    is_anonymous = False
    is_authenticated = True

    def __init__(self, payload: dict):
        self.payload = payload

        # Identifiant universel — ne change jamais même si l'email change
        self.sub: str = payload.get("sub", "")

        # Infos de base synchronisées depuis le token
        self.email: str = payload.get("email", "")
        self.username: str = payload.get("preferred_username", "")
        self.first_name: str = payload.get("given_name", "")
        self.last_name: str = payload.get("family_name", "")

        # Rôles
        self._realm_roles: list[str] = extract_realm_roles(payload)

        config = get_keycloak_config()
        self._client_id: str = config.get("CLIENT_ID", "")
        self._client_roles: list[str] = extract_client_roles(payload, self._client_id)

    # Django attend ces attributs sur request.user
    @property
    def pk(self):
        return self.sub

    @property
    def id(self):
        return self.sub

    def __str__(self):
        return self.username or self.email

    def __repr__(self):
        return f"<KeycloakUser sub={self.sub} email={self.email}>"

    # ------------------------------------------------------------------ #
    #  Méthodes de vérification des rôles                                 #
    # ------------------------------------------------------------------ #

    def has_realm_role(self, role: str) -> bool:
        """Vérifie un rôle global realm (ex: 'eneo-admin', 'staff', 'user')."""
        return role in self._realm_roles

    def has_client_role(self, role: str, client_id: str | None = None) -> bool:
        """
        Vérifie un rôle client (ex: 'zury:read', 'zury:write').
        Si client_id est None, utilise le CLIENT_ID configuré.
        """
        if client_id:
            roles = extract_client_roles(self.payload, client_id)
            return role in roles
        return role in self._client_roles

    def has_role(self, role: str) -> bool:
        """Raccourci — vérifie dans realm_roles ET client_roles."""
        return self.has_realm_role(role) or self.has_client_role(role)

    @property
    def realm_roles(self) -> list[str]:
        return self._realm_roles

    @property
    def client_roles(self) -> list[str]:
        return self._client_roles

    # ------------------------------------------------------------------ #
    #  Compatibilité Django                                               #
    # ------------------------------------------------------------------ #

    def has_perm(self, perm, obj=None) -> bool:
        return self.has_realm_role("eneo-admin")

    def has_module_perms(self, app_label) -> bool:
        return self.has_realm_role("eneo-admin")


class KeycloakAuthentication(BaseAuthentication):
    """
    Classe d'authentification DRF basée sur les tokens JWT Keycloak.

    À ajouter dans settings.py du projet :
        REST_FRAMEWORK = {
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "eneo_common.authentication.KeycloakAuthentication",
            ],
        }
    """

    def authenticate(self, request):
        config = get_keycloak_config()
        header = config["TOKEN_HEADER"]
        prefix = config["TOKEN_PREFIX"]

        auth_header = request.headers.get(header, "")

        if not auth_header.startswith(f"{prefix} "):
            # Pas de token → DRF passe à la prochaine classe d'auth
            return None

        token = auth_header[len(prefix) + 1:]

        if not token:
            raise AuthenticationFailed("Token manquant après le préfixe Bearer.")

        try:
            payload = decode_token(token)
        except KeycloakTokenError as e:
            raise AuthenticationFailed(str(e))
        except KeycloakUnavailableError:
            logger.error("Keycloak indisponible lors de la validation du token.")
            raise AuthenticationFailed(
                "Service d'authentification temporairement indisponible. "
                "Réessayez dans quelques instants."
            )
        except KeycloakConfigError as e:
            logger.critical(f"Configuration Keycloak manquante : {e}")
            raise AuthenticationFailed("Erreur de configuration du serveur.")

        user = KeycloakUser(payload)
        return (user, token)

    def authenticate_header(self, request):
        return 'Bearer realm="eneo-group"'
