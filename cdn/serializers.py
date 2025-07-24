from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    Folder, File, FileVersion, Share, ShareAccessLog, 
    StarredItem, ActivityLog, TrashItem, FileAnalytics, ProcessingJob
)
from my_auth.models import Profile

User = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    
    class Meta:
        model = Profile
        fields = ['id', 'username', 'email', 'full_name', 'profile_picture']

class FolderSerializer(serializers.ModelSerializer):
    owner_detail = ProfileSerializer(source='owner', read_only=True)
    children_count = serializers.SerializerMethodField()
    files_count = serializers.SerializerMethodField()
    full_path = serializers.CharField(source='get_full_path', read_only=True)
    
    class Meta:
        model = Folder
        fields = [
            'id', 'name', 'parent', 'owner', 'owner_detail', 'path', 'is_root',
            'children_count', 'files_count', 'full_path', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'owner', 'path', 'created_at', 'updated_at']
    
    def get_children_count(self, obj):
        return obj.children.count()
    
    def get_files_count(self, obj):
        return obj.files.count()

class FileVersionSerializer(serializers.ModelSerializer):
    created_by_detail = ProfileSerializer(source='created_by', read_only=True)
    file_size_human = serializers.SerializerMethodField()
    
    class Meta:
        model = FileVersion
        fields = [
            'id', 'version_number', 'file_size', 'file_size_human',
            'created_by', 'created_by_detail', 'created_at'
        ]
    
    def get_file_size_human(self, obj):
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

class FileSerializer(serializers.ModelSerializer):
    owner_detail = ProfileSerializer(source='owner', read_only=True)
    folder_detail = FolderSerializer(source='folder', read_only=True)
    versions = FileVersionSerializer(many=True, read_only=True)
    versions_count = serializers.SerializerMethodField()
    is_starred = serializers.SerializerMethodField()
    
    class Meta:
        model = File
        fields = [
            'id', 'filename', 'original_filename', 'folder', 'folder_detail',
            'owner', 'owner_detail', 'file_size', 'file_size_human', 'mime_type',
            'file_extension', 'storage_path', 'cdn_url', 'thumbnail_url', 'preview_url',
            'is_processed', 'processing_status', 'versions', 'versions_count',
            'is_starred', 'created_at', 'updated_at', 'last_accessed'
        ]
        read_only_fields = [
            'id', 'owner', 'file_size_human', 'storage_path', 'md5_hash',
            'sha256_hash', 'upload_ip', 'created_at', 'updated_at', 'last_accessed'
        ]
    
    def get_versions_count(self, obj):
        return obj.versions.count()
    
    def get_is_starred(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            profile = Profile.objects.get(user=request.user)
            return StarredItem.objects.filter(
                user=profile,
                resource_type='file',
                resource_id=obj.id
            ).exists()
        return False

class ShareSerializer(serializers.ModelSerializer):
    owner_detail = ProfileSerializer(source='owner', read_only=True)
    resource_detail = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(read_only=True)
    can_download = serializers.BooleanField(read_only=True)
    access_logs_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Share
        fields = [
            'id', 'resource_type', 'resource_id', 'owner', 'owner_detail', 'permission_level',
            'is_public', 'public_token', 'password_protected', 'expires_at',
            'allow_download', 'allow_preview', 'download_limit', 'download_count',
            'resource_detail', 'is_expired', 'can_download', 'access_logs_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'owner', 'public_token', 'download_count', 'created_at', 'updated_at'
        ]
    
    def get_resource_detail(self, obj):
        resource = obj.resource_object
        if obj.resource_type == 'file' and resource:
            return {
                'id': resource.id,
                'filename': resource.filename,
                'file_size': resource.file_size,
                'mime_type': resource.mime_type,
                'thumbnail_url': resource.thumbnail_url
            }
        elif obj.resource_type == 'folder' and resource:
            return {
                'id': resource.id,
                'name': resource.name,
                'path': resource.path,
                'files_count': resource.files.count()
            }
        return None
    
    def get_access_logs_count(self, obj):
        return obj.access_logs.count()

class ShareAccessLogSerializer(serializers.ModelSerializer):
    accessed_by_detail = ProfileSerializer(source='accessed_by_user', read_only=True)
    share_detail = ShareSerializer(source='share', read_only=True)
    
    class Meta:
        model = ShareAccessLog
        fields = [
            'id', 'share', 'share_detail', 'accessed_by_user', 'accessed_by_detail',
            'access_type', 'ip_address', 'user_agent', 'accessed_at'
        ]
        read_only_fields = ['id', 'accessed_at']

class StarredItemSerializer(serializers.ModelSerializer):
    user_detail = ProfileSerializer(source='user', read_only=True)
    resource_detail = serializers.SerializerMethodField()
    
    class Meta:
        model = StarredItem
        fields = [
            'id', 'user', 'user_detail', 'resource_type', 'resource_id',
            'resource_detail', 'starred_at'
        ]
        read_only_fields = ['id', 'user', 'starred_at']
    
    def get_resource_detail(self, obj):
        if obj.resource_type == 'file':
            try:
                file_obj = File.objects.get(id=obj.resource_id)
                return {
                    'id': file_obj.id,
                    'filename': file_obj.filename,
                    'mime_type': file_obj.mime_type,
                    'file_size': file_obj.file_size,
                    'thumbnail_url': file_obj.thumbnail_url
                }
            except File.DoesNotExist:
                pass
        elif obj.resource_type == 'folder':
            try:
                folder_obj = Folder.objects.get(id=obj.resource_id)
                return {
                    'id': folder_obj.id,
                    'name': folder_obj.name,
                    'path': folder_obj.path
                }
            except Folder.DoesNotExist:
                pass
        return None

class ActivityLogSerializer(serializers.ModelSerializer):
    user_detail = ProfileSerializer(source='user', read_only=True)
    
    class Meta:
        model = ActivityLog
        fields = [
            'id', 'user', 'user_detail', 'action_type', 'resource_type',
            'resource_id', 'resource_name', 'metadata', 'ip_address',
            'user_agent', 'created_at'
        ]
        read_only_fields = ['id', 'user', 'created_at']

class TrashItemSerializer(serializers.ModelSerializer):
    user_detail = ProfileSerializer(source='user', read_only=True)
    days_until_permanent_delete = serializers.SerializerMethodField()
    
    class Meta:
        model = TrashItem
        fields = [
            'id', 'user', 'user_detail', 'resource_type', 'resource_id',
            'original_name', 'original_path', 'deleted_at', 'permanent_delete_at',
            'days_until_permanent_delete'
        ]
        read_only_fields = ['id', 'user', 'deleted_at', 'permanent_delete_at']
    
    def get_days_until_permanent_delete(self, obj):
        from django.utils import timezone
        if obj.permanent_delete_at:
            delta = obj.permanent_delete_at - timezone.now()
            return max(0, delta.days)
        return 0

class FileAnalyticsSerializer(serializers.ModelSerializer):
    file_detail = FileSerializer(source='file', read_only=True)
    
    class Meta:
        model = FileAnalytics
        fields = [
            'id', 'file', 'file_detail', 'access_date', 'view_count',
            'download_count', 'country_code', 'region', 'city',
            'avg_response_time', 'cache_hit_ratio', 'referrer_domain'
        ]
        read_only_fields = ['id']

class ProcessingJobSerializer(serializers.ModelSerializer):
    file_detail = FileSerializer(source='file', read_only=True)
    
    class Meta:
        model = ProcessingJob
        fields = [
            'id', 'file', 'file_detail', 'job_type', 'status', 'priority',
            'attempts', 'max_attempts', 'error_message', 'result_data',
            'created_at', 'started_at', 'completed_at'
        ]
        read_only_fields = [
            'id', 'attempts', 'error_message', 'result_data',
            'created_at', 'started_at', 'completed_at'
        ]

# File Upload Serializer - Client provides CDN URL and hashes
class FileUploadSerializer(serializers.Serializer):
    filename = serializers.CharField(max_length=255)
    original_filename = serializers.CharField(max_length=255, required=False)
    cdn_url = serializers.URLField()
    file_size = serializers.IntegerField(min_value=1)
    mime_type = serializers.CharField(max_length=100)
    md5_hash = serializers.CharField(max_length=32)
    sha256_hash = serializers.CharField(max_length=64)
    folder_id = serializers.UUIDField(required=False)
    
    def validate(self, data):
        if 'original_filename' not in data:
            data['original_filename'] = data['filename']
        return data

# Folder Creation Serializer
class FolderCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Folder
        fields = ['name', 'parent']
    
    def validate(self, data):
        request = self.context['request']
        profile = Profile.objects.get(user=request.user)
        
        # Check if folder with same name exists in parent
        parent = data.get('parent')
        if Folder.objects.filter(
            owner=profile,
            parent=parent,
            name=data['name']
        ).exists():
            raise serializers.ValidationError(
                "A folder with this name already exists in the specified location."
            )
        
        return data