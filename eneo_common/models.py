import uuid
from django.db import models



class AbstractKeycloakUser(models.Model):
    """
    Modèle Django abstrait pour les utilisateurs authentifiés via Keycloak.

    Le `sub` (UUID Keycloak) est la clé primaire — jamais l'email.
    Il est immuable et ne change jamais, même si l'utilisateur change son email.

    Chaque projet hérite de ce modèle et ajoute ses champs métier :

        # Dans Zury
        class ZuryUser(AbstractKeycloakUser):
            workspace = models.CharField(max_length=100)

        # Dans Mosala
        class MosalaUser(AbstractKeycloakUser):
            job_title = models.CharField(max_length=100)

        # Dans eneo-account
        class EneoAccount(AbstractKeycloakUser):
            avatar = models.URLField(blank=True)

    La lazy creation se fait via get_or_create_from_token() :
        user, created = ZuryUser.get_or_create_from_token(token_payload)
    """

    # ------------------------------------------------------------------ #
    #  Clé primaire                                                        #
    # ------------------------------------------------------------------ #

    sub = models.UUIDField(
        primary_key=True,
        editable=False,
        help_text="Identifiant universel Keycloak (sub). Jamais modifié.",
    )

    # ------------------------------------------------------------------ #
    #  Claims standards JWT — synchronisés à chaque connexion             #
    # ------------------------------------------------------------------ #

    email = models.EmailField(
        unique=True,
        help_text="Synchronisé depuis le claim 'email' du token JWT.",
    )
    username = models.CharField(
        max_length=150,
        unique=True,
        help_text="Synchronisé depuis le claim 'preferred_username' du token JWT.",
    )
    first_name = models.CharField(
        max_length=150,
        blank=True,
        help_text="Synchronisé depuis le claim 'given_name' du token JWT.",
    )
    last_name = models.CharField(
        max_length=150,
        blank=True,
        help_text="Synchronisé depuis le claim 'family_name' du token JWT.",
    )

    # ------------------------------------------------------------------ #
    #  Attributs custom Keycloak — configurés via mappers dans le realm   #
    # ------------------------------------------------------------------ #

    GENRE_CHOICES = [
        ("M", "Homme"),
        ("F", "Femme"),
    ]
    genre = models.CharField(
        max_length=1,
        choices=GENRE_CHOICES,
        blank=True,
        help_text="Synchronisé depuis l'attribut custom Keycloak 'gender'.",
    )
    tel = models.CharField(
        max_length=20,
        blank=True,
        help_text="Synchronisé depuis l'attribut custom Keycloak 'phone_number'.",
    )

    # ------------------------------------------------------------------ #
    #  Métadonnées                                                         #
    # ------------------------------------------------------------------ #

    date_joined = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True

    def __str__(self):
        return self.username or self.email

    # ------------------------------------------------------------------ #
    #  Lazy creation + synchronisation depuis le token JWT                #
    # ------------------------------------------------------------------ #

    @classmethod
    def get_or_create_from_token(cls, payload: dict) -> tuple["AbstractKeycloakUser", bool]:
        """
        Lazy creation : crée le profil utilisateur au premier appel API,
        et synchronise toutes les infos depuis le token à chaque connexion.

        Retourne (instance, created) comme Django get_or_create.

        Utilisation dans une vue :
            user, created = EneoAccount.get_or_create_from_token(request.user.payload)
        """
        sub = payload.get("sub")
        if not sub:
            raise ValueError("Le payload JWT ne contient pas de 'sub'.")

        defaults = {
            "email": payload.get("email", ""),
            "username": payload.get("preferred_username", ""),
            "first_name": payload.get("given_name", ""),
            "last_name": payload.get("family_name", ""),
            "genre": payload.get("gender", ""),
            "tel": payload.get("phone_number", ""),
        }

        instance, created = cls.objects.get_or_create(
            sub=uuid.UUID(sub) if isinstance(sub, str) else sub,
            defaults=defaults,
        )

        if not created:
            updated = False
            for field, value in defaults.items():
                if getattr(instance, field) != value and value:
                    setattr(instance, field, value)
                    updated = True
            if updated:
                instance.save(update_fields=list(defaults.keys()) + ["last_seen"])

        return instance, created

    # ------------------------------------------------------------------ #
    #  Propriétés utilitaires                                              #
    # ------------------------------------------------------------------ #

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip() or self.username

    @property
    def genre_display(self) -> str:
        return dict(self.GENRE_CHOICES).get(self.genre, "")