"""
eneo-common — Package SSO Keycloak pour les projets Eneo Group.

Exports principaux :
    from eneo_common.authentication import KeycloakAuthentication, KeycloakUser
    from eneo_common.permissions import (
        IsKeycloakAuthenticated,
        IsEneoAdmin, IsStaff, IsUser,
        IsZuryUser, CanReadZury, CanWriteZury,
        require_role, require_client_role,
    )
    from eneo_common.middleware import KeycloakMiddleware
    from eneo_common.models import AbstractKeycloakUser
"""

__version__ = "0.1.0"
__author__ = "Eneo Group"
