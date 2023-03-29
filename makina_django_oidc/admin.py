from django.contrib import admin


class OIDCSessionAdmin(admin.ModelAdmin):
    readonly_fields = ("sid", "uid", "cache_session_key")
    list_display = ["sid", "uid", "sub", "cache_session_key"]
