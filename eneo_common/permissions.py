from rest_framework.permissions import BasePermission

from eneo_common.authentication import KeycloakUser


def _is_keycloak_user(request) -> bool:
    """Vérifie que request.user est bien un KeycloakUser authentifié."""
    return isinstance(request.user, KeycloakUser) and request.user.is_authenticated


# ------------------------------------------------------------------ #
#  Permissions de base                                                #
# ------------------------------------------------------------------ #

class IsKeycloakAuthenticated(BasePermission):
    """
    Autorise uniquement les requêtes avec un token Keycloak valide.
    Équivalent de IsAuthenticated mais spécifique à Keycloak.
    """
    message = "Authentification requise. Fournissez un token JWT valide."

    def has_permission(self, request, view):
        return _is_keycloak_user(request)


# ------------------------------------------------------------------ #
#  Factory dynamique — pour les rôles non encore définis             #
# ------------------------------------------------------------------ #

def require_role(role: str, realm: bool = True):
    """
    Crée dynamiquement une permission pour n'importe quel rôle Keycloak.

    Utilisation directe dans une vue (sans créer de classe) :
        permission_classes = [require_role("nouveau-role")]

    Paramètres :
        role  : nom du rôle Keycloak
        realm : True = vérifie dans realm_access (défaut)
                False = vérifie dans resource_access (rôles client)
    """
    class DynamicRolePermission(BasePermission):
        message = f"Rôle requis : '{role}'."

        def has_permission(self, request, view):
            if not _is_keycloak_user(request):
                return False
            if realm:
                return request.user.has_realm_role(role)
            return request.user.has_client_role(role)

    DynamicRolePermission.__name__ = f"Has_{role.replace('-', '_')}_Role"
    return DynamicRolePermission


def require_client_role(role: str, client_id: str | None = None):
    """
    Crée une permission pour un rôle client spécifique.

    Utilisation :
        permission_classes = [require_client_role("zury:write")]
        permission_classes = [require_client_role("mosala:admin", client_id="mosala-web")]
    """
    class ClientRolePermission(BasePermission):
        message = f"Rôle client requis : '{role}'."

        def has_permission(self, request, view):
            if not _is_keycloak_user(request):
                return False
            return request.user.has_client_role(role, client_id=client_id)

    ClientRolePermission.__name__ = f"HasClientRole_{role.replace(':', '_').replace('-', '_')}"
    return ClientRolePermission


# ------------------------------------------------------------------ #
#  Permissions nommées — rôles actuels Eneo Group                    #
#  Ajouter ici les nouveaux rôles quand ils arrivent dans Keycloak   #
# ------------------------------------------------------------------ #

# Rôles realm (realm_access.roles)
IsEneoAdmin = require_role("eneo-admin")
IsStaff = require_role("staff")
IsUser = require_role("user")

# Rôles client Zury (resource_access.zury-web.roles)
CanReadZury = require_client_role("zury:read")
CanWriteZury = require_client_role("zury:write")

# Accès global à Zury — avoir au moins un rôle zury:*
class IsZuryUser(BasePermission):
    """
    Vérifie que l'utilisateur a accès à l'application Zury.
    Condition : avoir au moins 'zury:read' ou 'zury:write'.
    """
    message = "Accès à Zury non autorisé."

    def has_permission(self, request, view):
        if not _is_keycloak_user(request):
            return False
        user = request.user
        return user.has_client_role("zury:read") or user.has_client_role("zury:write")


# ------------------------------------------------------------------ #
#  Combinaison de permissions (AND logique)                          #
# ------------------------------------------------------------------ #

class IsAuthenticatedAndZuryUser(BasePermission):
    """Authentifié + accès Zury. Raccourci pratique."""
    message = "Token valide et accès Zury requis."

    def has_permission(self, request, view):
        return (
            _is_keycloak_user(request)
            and (
                request.user.has_client_role("zury:read")
                or request.user.has_client_role("zury:write")
            )
        )
