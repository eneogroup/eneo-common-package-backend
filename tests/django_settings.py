"""
Settings Django minimaux pour faire tourner les tests du package
sans avoir un projet Django complet.
"""

SECRET_KEY = "test-secret-key-not-for-production"
DEBUG = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
KEYCLOAK_CONFIG = {
    "SERVER_URL": "https://sso.eneogroup.com",
    "REALM": "eneogroup-si",
    "CLIENT_ID": "eneo-backend",
    "CLIENT_SECRET": "test-secret",
    "VERIFY_SSL": False,
    "TOKEN_HEADER": "Authorization",
    "TOKEN_PREFIX": "Bearer",
}
