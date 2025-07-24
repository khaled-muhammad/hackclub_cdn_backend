from django.contrib import admin
from django.utils.html import format_html
from .models import *

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ['filename', 'owner', 'file_size_human', 'mime_type', 'created_at']
    list_filter = ['mime_type', 'processing_status']
    search_fields = ['filename', 'original_filename', 'owner__user__email']
    readonly_fields = ['id', 'md5_hash', 'sha256_hash', 'created_at', 'updated_at']

admin.site.register(Folder)
admin.site.register(TrashItem)
admin.site.register(Share)

# @admin.register(Share)
# class ShareAdmin(admin.ModelAdmin):
#     list_display = ['resource_type', 'owner', 'permission_level', 'is_public', 'expires_at']
#     list_filter = ['resource_type', 'permission_level', 'is_public']
#     search_fields = ['owner__email', 'public_token']