from django.db import models


class OIDCSession(models.Model):
    objects: models.Manager["OIDCSession"]

    id = models.BigAutoField(primary_key=True)

    # Used by pyoidc to save the client when no session state is available
    state = models.TextField()

    # Defined in https://openid.net/specs/openid-connect-session-1_0.html, use to find back a session using 'sid' from a logout JWT
    session_state = models.TextField(null=True)

    # Used to find back a session using 'sub' from a logout JWT
    sub = models.TextField()

    # Django cache session key used to log out users by finding a session in a SessionStore and deleting it
    cache_session_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        if self.session_state:
            return f"Session with id : {self.session_state}"
        else:
            return f"Session without id, sub : {self.sub}"
