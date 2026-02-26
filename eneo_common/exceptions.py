class EneoCommonError(Exception):
    """Erreur de base du package eneo-common."""
    pass


class KeycloakUnavailableError(EneoCommonError):
    """Keycloak est temporairement indisponible."""
    pass


class KeycloakTokenError(EneoCommonError):
    """Le token JWT est invalide, expiré ou mal formé."""
    pass


class KeycloakConfigError(EneoCommonError):
    """La configuration Keycloak est manquante ou incorrecte."""
    pass
