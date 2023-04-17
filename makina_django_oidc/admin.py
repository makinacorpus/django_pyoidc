from importlib import import_module

from django.conf import settings
from django.contrib import admin

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


class OIDCSessionAdmin(admin.ModelAdmin):
    readonly_fields = (
        "state",
        "session_state",
        "has_session_management",
        "sub",
        "cache_session_key",
        "session_is_active",
        "created_at",
    )
    list_display = [
        "id",
        "has_session_management",
        "session_is_active",
        "sub",
        "created_at",
    ]

    def has_session_management(self, obj) -> bool:
        return obj.session_state is not None

    def session_is_active(self, obj) -> bool:
        s = SessionStore()
        return obj.cache_session_key is not None and s.exists(obj.cache_session_key)

    has_session_management.boolean = True
    session_is_active.boolean = True
