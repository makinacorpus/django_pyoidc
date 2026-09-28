from django.db import models
from django.utils import timezone


class OIDCSession(models.Model):
    objects: models.Manager["OIDCSession"]

    id = models.BigAutoField(primary_key=True)

    # Used by pyoidc to save the client when no session state is available
    state = models.TextField()

    # Defined in https://openid.net/specs/openid-connect-session-1_0.html, use to find back a session using 'sid' from a logout JWT
    session_state = models.TextField(null=True)

    # Used to find back a session using 'sub' from a logout JWT
    sub = models.TextField()

    # Used by the session expiration control middleware for refresh tokens managment
    # default is set to manage existing records during update migration
    # we do not use auto_now_add because we usually set this value in the
    # code (and it's based on token data, not on now())
    expiration = models.DateTimeField(default=timezone.now, null=False, blank=False)

    # support for multi-providers config
    # op_name can be used to fetch settings, leading to refresh token actions
    op_name = models.TextField(default="unknown", null=False, blank=False)

    # Django cache session key used to log out users by finding a session in a SessionStore and deleting it
    cache_session_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        if self.session_state:
            return f"Session with id : {self.session_state}, ({self.op_name})"
        else:
            return f"Session without id, sub : {self.sub}, ({self.op_name})"
