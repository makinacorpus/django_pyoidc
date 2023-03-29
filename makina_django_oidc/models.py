from django.db import models


class OIDCSession(models.Model):
    id = models.BigAutoField(primary_key=True)
    sid = models.TextField()
    sub = models.TextField()
    uid = models.TextField()
    cache_session_key = models.TextField()
