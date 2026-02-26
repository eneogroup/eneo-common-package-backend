# eneo-common

Package SSO Keycloak pour les projets Django/DRF d'Eneo Group.  
Partagé entre **Zury**, **Mosala**, **eneo-account** et tous les futurs projets.

---

## Installation

```bash
pip install git+https://github.com/eneogroup/eneo-common.git
```

Pour une version spécifique :
```bash
pip install git+https://github.com/eneogroup/eneo-common.git@v0.1.0
```

---

## Configuration

Dans `settings.py` de votre projet Django :

```python
import os

KEYCLOAK_CONFIG = {
    "SERVER_URL": os.environ["KEYCLOAK_URL"],        # https://sso.eneogroup.com
    "REALM": os.environ["KEYCLOAK_REALM"],           # eneogroup-si
    "CLIENT_ID": os.environ["KEYCLOAK_CLIENT_ID"],   # eneo-backend
    "CLIENT_SECRET": os.environ["KEYCLOAK_CLIENT_SECRET"],
    "VERIFY_SSL": True,                              # Toujours True en production
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "eneo_common.authentication.KeycloakAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "eneo_common.permissions.IsKeycloakAuthenticated",
    ],
}
```

---

## Utilisation

### Protéger une vue

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from eneo_common.permissions import IsKeycloakAuthenticated, IsEneoAdmin, IsZuryUser, require_role

class ProfilView(APIView):
    permission_classes = [IsKeycloakAuthenticated]

    def get(self, request):
        user = request.user  # KeycloakUser
        return Response({
            "sub": user.sub,
            "email": user.email,
            "roles": user.realm_roles,
        })


class AdminView(APIView):
    permission_classes = [IsEneoAdmin]

    def get(self, request):
        return Response({"message": "Accès admin accordé"})


# Avec un rôle dynamique (pas besoin de créer une classe)
class NouveauRoleView(APIView):
    permission_classes = [require_role("nouveau-role")]

    def get(self, request):
        return Response({"ok": True})
```

### Modèle utilisateur dans votre projet

```python
# users/models.py dans Zury
from django.db import models
from eneo_common.models import AbstractKeycloakUser

class ZuryUser(AbstractKeycloakUser):
    # Champs spécifiques à Zury
    workspace = models.CharField(max_length=100, blank=True)
    avatar_url = models.URLField(blank=True)

    class Meta:
        db_table = "zury_users"


# Dans une vue — lazy creation au premier appel
class MeView(APIView):
    permission_classes = [IsKeycloakAuthenticated]

    def get(self, request):
        user, created = ZuryUser.get_or_create_from_token(request.user.payload)
        return Response({
            "sub": str(user.sub),
            "email": user.email,
            "new_user": created,
        })
```

### Middleware (optionnel)

```python
# settings.py
MIDDLEWARE = [
    ...
    "eneo_common.middleware.KeycloakMiddleware",
]

# Dans n'importe quelle vue ou middleware suivant
def ma_vue(request):
    payload = request.user_payload  # dict ou None si pas de token
```

---

## Permissions disponibles

| Permission | Description |
|---|---|
| `IsKeycloakAuthenticated` | Token JWT valide requis |
| `IsEneoAdmin` | Rôle `eneo-admin` requis |
| `IsStaff` | Rôle `staff` requis |
| `IsUser` | Rôle `user` requis |
| `IsZuryUser` | Rôle `zury:read` ou `zury:write` requis |
| `CanReadZury` | Rôle `zury:read` requis |
| `CanWriteZury` | Rôle `zury:write` requis |
| `require_role("nom-role")` | Rôle realm dynamique |
| `require_client_role("role")` | Rôle client dynamique |

---

## Lancer les tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Variables d'environnement

Voir `.env.example` pour la liste complète.

---

## Versioning

- `main` — branche stable
- Tagger les releases : `git tag v0.1.0 && git push --tags`
- Dans `requirements.txt` des projets : `eneo-common @ git+https://github.com/eneogroup/eneo-common.git@v0.1.0`
