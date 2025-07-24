from django.db import models
import uuid
import os
from django.db import models
from django.core.validators import FileExtensionValidator
from django.utils import timezone
from my_auth.models import Profile
import secrets

# Create your models here.

PERMISSION_LEVELS = [
    ('view', 'View Only'),
    ('download', 'Download'),
    ('edit', 'Edit'),
    ('admin', 'Admin'),
]

class Folder(models.Model):
    id      = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name    = models.CharField(max_length=255)
    parent  = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    owner   = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='folders')
    path    = models.TextField()  # Full path for quick lookups
    is_root = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    is_trashed = models.BooleanField(default=False)

    class Meta:
        unique_together = ['owner', 'parent', 'name']
        indexes = [
            models.Index(fields=['owner', 'path']),
            models.Index(fields=['parent']),
            models.Index(fields=['owner', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.owner.user.username}/{self.path}"
    
    def get_full_path(self):
        if self.parent:
            return f"{self.parent.get_full_path()}/{self.name}"
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.path:
            self.path = self.get_full_path()
        super().save(*args, **kwargs)

class File(models.Model):
    PROCESSING_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id                  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    filename            = models.CharField(max_length=255)
    original_filename   = models.CharField(max_length=255)
    folder              = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='files')
    owner               = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='files')
    
    file_size       = models.BigIntegerField()
    mime_type       = models.CharField(max_length=100)
    file_extension  = models.CharField(max_length=20, blank=True)
    
    storage_path    = models.TextField()
    storage_bucket  = models.CharField(max_length=255, blank=True)
    
    md5_hash    = models.CharField(max_length=32, blank=True, db_index=True)
    sha256_hash = models.CharField(max_length=64, blank=True, db_index=True)
    
    cdn_url             = models.URLField(blank=True, null=True)
    cdn_edge_locations  = models.JSONField(default=list, blank=True)
    
    is_processed      = models.BooleanField(default=False)
    processing_status = models.CharField(max_length=50, choices=PROCESSING_STATUS_CHOICES, default='pending')
    thumbnail_url     = models.URLField(blank=True, null=True)
    preview_url       = models.URLField(blank=True, null=True)
    
    upload_ip     = models.GenericIPAddressField(null=True, blank=True)
    created_at    = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)
    last_accessed = models.DateTimeField(auto_now_add=True)
    
    is_trashed = models.BooleanField(default=False)

    class Meta:
        unique_together = ['owner', 'folder', 'filename']
        indexes = [
            models.Index(fields=['owner']),
            models.Index(fields=['folder']),
            models.Index(fields=['md5_hash', 'sha256_hash']),
            models.Index(fields=['mime_type']),
            models.Index(fields=['file_size']),
            models.Index(fields=['owner', 'created_at']),
            models.Index(fields=['processing_status']),
        ]
    
    def __str__(self):
        return f"{self.owner.user.username}/{self.folder.path}/{self.filename}"
    
    @property
    def file_size_human(self):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} PB"
    
    def save(self, *args, **kwargs):
        if not self.file_extension and self.original_filename:
            self.file_extension = os.path.splitext(self.original_filename)[1].lower()
        super().save(*args, **kwargs)

class FileVersion(models.Model):
    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file            = models.ForeignKey(File, on_delete=models.CASCADE, related_name='versions')
    version_number  = models.IntegerField()
    storage_path    = models.TextField()
    file_size       = models.BigIntegerField()
    created_by      = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True, blank=True)
    created_at      = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['file', 'version_number']
        indexes = [
            models.Index(fields=['file']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.file.filename} v{self.version_number}"

class Share(models.Model):
    RESOURCE_TYPES = [
        ('file', 'File'),
        ('folder', 'Folder'),
    ]
    
    id                  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    resource_type       = models.CharField(max_length=10, choices=RESOURCE_TYPES)
    resource_id         = models.UUIDField()
    owner               = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='owned_shares')
    shared_with         = models.ManyToManyField(
        Profile,
        through='SharedUserPermission',
        related_name='received_shared_resources'
    )
    permission_level    = models.CharField(max_length=20, choices=PERMISSION_LEVELS, default='view')
    
    is_public           = models.BooleanField(default=False)
    public_token        = models.CharField(max_length=255, unique=True, blank=True)
    password_protected  = models.BooleanField(default=False)
    password_hash       = models.CharField(max_length=255, blank=True)
    
    expires_at          = models.DateTimeField(null=True, blank=True)
    
    allow_download = models.BooleanField(default=True)
    allow_preview  = models.BooleanField(default=True)
    download_limit = models.IntegerField(null=True, blank=True)
    download_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['owner']),
            models.Index(fields=['public_token']),
            models.Index(fields=['is_public', 'expires_at']),
        ]
    
    def __str__(self):
        return f"Share: {self.resource_type} {self.resource_id} by {self.owner.username}"
    
    def save(self, *args, **kwargs):
        if self.is_public and not self.public_token:
            self.public_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def can_download(self):
        if not self.allow_download:
            return False
        if self.download_limit and self.download_count >= self.download_limit:
            return False
        return True
    
    @property
    def resource_object(self):
        if self.resource_type == 'file':
            return File.objects.filter(id=self.resource_id).first()
        elif self.resource_type == 'folder':
            return Folder.objects.filter(id=self.resource_id).first()
        return None

class SharedUserPermission(models.Model):
    share               = models.ForeignKey(Share, on_delete=models.CASCADE)
    user                = models.ForeignKey(Profile, on_delete=models.CASCADE)
    permission_level    = models.CharField(max_length=20, choices=PERMISSION_LEVELS, default='view')
    created_at          = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['share', 'user']

class ShareAccessLog(models.Model):
    ACCESS_TYPES = [
        ('view', 'View'),
        ('download', 'Download'),
        ('preview', 'Preview'),
    ]
    
    id               = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    share            = models.ForeignKey(Share, on_delete=models.CASCADE, related_name='access_logs')
    accessed_by_user = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True, blank=True)
    access_type      = models.CharField(max_length=20, choices=ACCESS_TYPES)
    ip_address       = models.GenericIPAddressField(null=True, blank=True)
    user_agent       = models.TextField(blank=True)
    accessed_at      = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['share']),
            models.Index(fields=['accessed_at']),
            models.Index(fields=['access_type']),
        ]
    
    def __str__(self):
        return f"{self.access_type} access to {self.share} at {self.accessed_at}"

class StarredItem(models.Model):
    RESOURCE_TYPES = [
        ('file', 'File'),
        ('folder', 'Folder'),
    ]
    
    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user            = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='starred_items')
    resource_type   = models.CharField(max_length=10, choices=RESOURCE_TYPES)
    resource_id     = models.UUIDField()
    starred_at      = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'resource_type', 'resource_id']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['starred_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} starred {self.resource_type} {self.resource_id}"

class ActivityLog(models.Model):
    ACTION_TYPES = [
        ('upload', 'Upload'),
        ('download', 'Download'),
        ('view', 'View'),
        ('share', 'Share'),
        ('delete', 'Delete'),
        ('restore', 'Restore'),
        ('move', 'Move'),
        ('rename', 'Rename'),
        ('copy', 'Copy'),
    ]
    
    RESOURCE_TYPES = [
        ('file', 'File'),
        ('folder', 'Folder'),
    ]
    
    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user            = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='activity_logs')
    action_type     = models.CharField(max_length=50, choices=ACTION_TYPES)
    resource_type   = models.CharField(max_length=10, choices=RESOURCE_TYPES, null=True, blank=True)
    resource_id     = models.UUIDField(null=True, blank=True)
    resource_name   = models.CharField(max_length=255, blank=True)
    metadata        = models.JSONField(default=dict, blank=True)  # Additional a.s data
    ip_address      = models.GenericIPAddressField(null=True, blank=True)
    user_agent      = models.TextField(blank=True)
    created_at      = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['action_type']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} {self.action_type} {self.resource_name or self.resource_type}"

class TrashItem(models.Model):
    RESOURCE_TYPES = [
        ('file', 'File'),
        ('folder', 'Folder'),
    ]
    
    id                  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user                = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='trash_items')
    resource_type       = models.CharField(max_length=10, choices=RESOURCE_TYPES)
    resource_id         = models.UUIDField()
    original_name       = models.CharField(max_length=255)
    original_path       = models.TextField(blank=True)
    deleted_at          = models.DateTimeField(auto_now_add=True)
    permanent_delete_at = models.DateTimeField()
    cdn_url             = models.URLField()

    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['permanent_delete_at']),
            models.Index(fields=['deleted_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.permanent_delete_at:
            from django.utils import timezone
            from datetime import timedelta
            self.permanent_delete_at = timezone.now() + timedelta(days=30)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Deleted: {self.original_name} by {self.user.user.username}"

class FileAnalytics(models.Model):
    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file        = models.ForeignKey(File, on_delete=models.CASCADE, related_name='analytics')
    access_date = models.DateField()
    
    view_count     = models.IntegerField(default=0)
    download_count = models.IntegerField(default=0)
    
    country_code = models.CharField(max_length=2, blank=True)
    region       = models.CharField(max_length=100, blank=True)
    city         = models.CharField(max_length=100, blank=True)
    
    avg_response_time = models.IntegerField(null=True, blank=True)  # ms
    cache_hit_ratio = models.DecimalField(max_digits=5, decimal_places=4, null=True, blank=True)
    
    referrer_domain = models.CharField(max_length=255, blank=True)
    
    class Meta:
        db_table = 'cdn_file_analytics'
        unique_together = ['file', 'access_date', 'country_code']
        indexes = [
            models.Index(fields=['file', 'access_date']),
            models.Index(fields=['access_date']),
            models.Index(fields=['country_code']),
        ]
    
    def __str__(self):
        return f"Analytics for {self.file.filename} on {self.access_date}"

class ProcessingJob(models.Model):
    JOB_TYPES = [
        ('thumbnail', 'Generate Thumbnail'),
        ('preview', 'Generate Preview'),
        ('virus_scan', 'Virus Scan'),
        ('metadata_extract', 'Extract Metadata'),
        ('compress', 'Compress File'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file            = models.ForeignKey(File, on_delete=models.CASCADE, related_name='processing_jobs')
    job_type        = models.CharField(max_length=50, choices=JOB_TYPES)
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    priority        = models.IntegerField(default=5)
    attempts        = models.IntegerField(default=0)
    max_attempts    = models.IntegerField(default=3)
    error_message   = models.TextField(blank=True)
    result_data     = models.JSONField(default=dict, blank=True)
    
    created_at      = models.DateTimeField(auto_now_add=True)
    started_at      = models.DateTimeField(null=True, blank=True)
    completed_at    = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['file']),
            models.Index(fields=['job_type']),
            models.Index(fields=['priority', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.job_type} job for {self.file.filename} ({self.status})"