import os
import time
import httpx
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse, Http404
from django.utils import timezone
from django.db.models import Q, Count, Sum
from django.db import transaction
from django.conf import settings

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView

from .models import (
    Folder, File, FileVersion, Share, ShareAccessLog, 
    StarredItem, ActivityLog, TrashItem, FileAnalytics, ProcessingJob
)
from .serializers import (
    FolderSerializer, FileSerializer, FileVersionSerializer, ShareSerializer,
    ShareAccessLogSerializer, StarredItemSerializer, ActivityLogSerializer,
    TrashItemSerializer, FileAnalyticsSerializer, ProcessingJobSerializer,
    FileUploadSerializer, FolderCreateSerializer
)
from my_auth.models import Profile

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class FolderViewSet(viewsets.ModelViewSet):
    serializer_class = FolderSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        return Folder.objects.filter(owner=profile).order_by('name')

    def perform_create(self, serializer):
        profile = Profile.objects.get(user=self.request.user)
        serializer.save(owner=profile)
        
        # Log activity
        ActivityLog.objects.create(
            user=profile,
            action_type='upload',
            resource_type='folder',
            resource_name=serializer.instance.name,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )

    def perform_destroy(self, instance):
        # Move folder to trash instead of permanent delete
        profile = Profile.objects.get(user=self.request.user)
        TrashItem.objects.create(
            user=profile,
            resource_type='folder',
            resource_id=instance.id,
            original_name=instance.name,
            original_path=instance.path,
        )
        ActivityLog.objects.create(
            user=profile,
            action_type='delete',
            resource_type='folder',
            resource_name=instance.name,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        super().perform_destroy(instance)

    def get_client_ip(self):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

    @action(detail=True, methods=['get'])
    def contents(self, request, pk=None):
        """Get folder contents (subfolders and files)"""
        folder = self.get_object()
        
        # Get subfolders
        subfolders = folder.children.all().order_by('name')
        folder_serializer = FolderSerializer(subfolders, many=True, context={'request': request})
        
        # Get files
        files = folder.files.all().order_by('filename')
        file_serializer = FileSerializer(files, many=True, context={'request': request})
        
        return Response({
            'folders': folder_serializer.data,
            'files': file_serializer.data
        })

    @action(detail=False, methods=['get'])
    def root(self, request):
        """Get root folders for the user"""
        profile = Profile.objects.get(user=request.user)
        
        # Get or create root folder
        root_folder, created = Folder.objects.get_or_create(
            owner=profile,
            is_root=True,
            defaults={'name': 'Root', 'path': ''}
        )
        
        # Get root contents
        subfolders = Folder.objects.filter(owner=profile, parent=root_folder).order_by('name')
        files = File.objects.filter(owner=profile, folder=root_folder).order_by('filename')
        
        folder_serializer = FolderSerializer(subfolders, many=True, context={'request': request})
        file_serializer = FileSerializer(files, many=True, context={'request': request})
        
        return Response({
            'root_folder': FolderSerializer(root_folder, context={'request': request}).data,
            'folders': folder_serializer.data,
            'files': file_serializer.data
        })

class FileViewSet(viewsets.ModelViewSet):
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        queryset = File.objects.filter(owner=profile)
        
        # Filter by folder if specified
        folder_id = self.request.query_params.get('folder_id')
        if folder_id:
            queryset = queryset.filter(folder_id=folder_id)
        
        # Search functionality
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(filename__icontains=search) | 
                Q(original_filename__icontains=search)
            )
        
        # Filter by file type
        file_type = self.request.query_params.get('type')
        if file_type:
            if file_type == 'images':
                queryset = queryset.filter(mime_type__startswith='image/')
            elif file_type == 'videos':
                queryset = queryset.filter(mime_type__startswith='video/')
            elif file_type == 'documents':
                queryset = queryset.filter(mime_type__in=[
                    'application/pdf', 'application/msword', 'application/vnd.ms-excel',
                    'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                ])
        
        return queryset.order_by('-created_at')

    def perform_destroy(self, instance):
        # Move to trash instead of permanent delete
        profile = Profile.objects.get(user=self.request.user)
        
        TrashItem.objects.create(
            user=profile,
            resource_type='file',
            resource_id=instance.id,
            original_name=instance.filename,
            original_path=instance.folder.path if instance.folder else ''
        )
        
        # Log activity
        ActivityLog.objects.create(
            user=profile,
            action_type='delete',
            resource_type='file',
            resource_name=instance.filename,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        
        super().perform_destroy(instance)

    def get_client_ip(self):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

    @action(detail=False, methods=['post'])
    def upload(self, request):
        """Register a file that was uploaded to CDN by client"""
        serializer = FileUploadSerializer(data=request.data)
        
        if serializer.is_valid():
            profile = Profile.objects.get(user=request.user)
            data = serializer.validated_data
            
            folder_id = data.get('folder_id')
            filename = data['filename']
            original_filename = data['original_filename']
            cdn_url = data['cdn_url']
            file_size = data['file_size']
            mime_type = data['mime_type']
            md5_hash = data['md5_hash']
            sha256_hash = data['sha256_hash']
            
            # Get folder or create root if not specified
            if folder_id:
                folder = get_object_or_404(Folder, id=folder_id, owner=profile)
            else:
                folder, _ = Folder.objects.get_or_create(
                    owner=profile,
                    is_root=True,
                    defaults={'name': 'Root', 'path': ''}
                )
            
            # Check for duplicates using provided hashes
            existing_file = File.objects.filter(
                owner=profile,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash
            ).first()
            
            if existing_file:
                return Response({
                    'message': 'File already exists',
                    'existing_file': FileSerializer(existing_file, context={'request': request}).data
                }, status=status.HTTP_409_CONFLICT)
            
            # Create file record with CDN URL
            file_instance = File.objects.create(
                filename=filename,
                original_filename=original_filename,
                folder=folder,
                owner=profile,
                file_size=file_size,
                mime_type=mime_type,
                storage_path='',  # No local storage path since file is on CDN
                cdn_url=cdn_url,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash,
                is_processed=True,  # Assume client-uploaded files are processed
                processing_status='completed',
                upload_ip=self.get_client_ip()
            )
            
            # Create processing jobs for thumbnails if needed
            if file_instance.mime_type.startswith('image/'):
                ProcessingJob.objects.create(
                    file=file_instance,
                    job_type='thumbnail',
                    priority=3  # Lower priority since file is already uploaded
                )
            
            # Log activity
            ActivityLog.objects.create(
                user=profile,
                action_type='upload',
                resource_type='file',
                resource_id=file_instance.id,
                resource_name=filename,
                metadata={
                    'file_size': file_size, 
                    'mime_type': mime_type,
                    'cdn_url': cdn_url,
                    'upload_method': 'client_cdn'
                },
                ip_address=self.get_client_ip(),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response(
                FileSerializer(file_instance, context={'request': request}).data,
                status=status.HTTP_201_CREATED
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Get download URL for a file"""
        file_instance = self.get_object()
        profile = Profile.objects.get(user=request.user)
        
        # Update last accessed time
        file_instance.last_accessed = timezone.now()
        file_instance.save(update_fields=['last_accessed'])
        
        # Log activity
        ActivityLog.objects.create(
            user=profile,
            action_type='download',
            resource_type='file',
            resource_id=file_instance.id,
            resource_name=file_instance.filename,
            ip_address=self.get_client_ip(),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Return the CDN URL for download
        if not file_instance.cdn_url:
            return Response({
                'error': 'File URL not available'
            }, status=status.HTTP_404_NOT_FOUND)
        
        return Response({
            'download_url': file_instance.cdn_url,
            'filename': file_instance.filename,
            'size': file_instance.file_size,
            'mime_type': file_instance.mime_type
        })

    @action(detail=True, methods=['post'])
    def star(self, request, pk=None):
        """Star/unstar a file"""
        file_instance = self.get_object()
        profile = Profile.objects.get(user=request.user)
        
        starred_item, created = StarredItem.objects.get_or_create(
            user=profile,
            resource_type='file',
            resource_id=file_instance.id
        )
        
        if not created:
            starred_item.delete()
            return Response({'starred': False})
        
        return Response({'starred': True})

    @action(detail=False, methods=['get'])
    def starred(self, request):
        """Get starred files"""
        profile = Profile.objects.get(user=request.user)
        starred_items = StarredItem.objects.filter(user=profile, resource_type='file')
        
        # Get the actual files
        file_ids = [item.resource_id for item in starred_items]
        files = File.objects.filter(id__in=file_ids, owner=profile)
        
        serializer = FileSerializer(files, many=True, context={'request': request})
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def recent(self, request):
        """Get recently accessed files"""
        profile = Profile.objects.get(user=request.user)
        recent_files = File.objects.filter(owner=profile).order_by('-last_accessed')[:20]
        
        serializer = FileSerializer(recent_files, many=True, context={'request': request})
        return Response(serializer.data)

class ShareViewSet(viewsets.ModelViewSet):
    serializer_class = ShareSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        return Share.objects.filter(
            Q(owner=profile) | Q(shared_with_user=profile)
        ).order_by('-created_at')

    def perform_create(self, serializer):
        profile = Profile.objects.get(user=self.request.user)
        serializer.save(owner=profile)

    @action(detail=False, methods=['get'])
    def public(self, request):
        """Access public share by token"""
        token = request.query_params.get('token')
        if not token:
            return Response({'error': 'Token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            share = Share.objects.get(public_token=token, is_public=True)
            if share.is_expired():
                return Response({'error': 'Share expired'}, status=status.HTTP_410_GONE)
            
            # Log access
            ShareAccessLog.objects.create(
                share=share,
                access_type='view',
                ip_address=self.get_client_ip(),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response(ShareSerializer(share, context={'request': request}).data)
            
        except Share.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=status.HTTP_404_NOT_FOUND)

    def get_client_ip(self):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ActivityLogSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        return ActivityLog.objects.filter(user=profile).order_by('-created_at')

class TrashViewSet(viewsets.ModelViewSet):
    serializer_class = TrashItemSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        return TrashItem.objects.filter(user=profile).order_by('-deleted_at')

    @action(detail=True, methods=['post'])
    def restore(self, request, pk=None):
        """Restore item from trash"""
        trash_item = self.get_object()
        
        # In a real implementation, you'd restore the actual file/folder
        # For now, just delete the trash record
        trash_item.delete()
        
        return Response({'message': 'Item restored successfully'})

    @action(detail=False, methods=['post'])
    def empty(self, request):
        """Empty entire trash"""
        profile = Profile.objects.get(user=request.user)
        TrashItem.objects.filter(user=profile).delete()
        
        return Response({'message': 'Trash emptied successfully'})

class DashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get dashboard statistics"""
        profile = Profile.objects.get(user=request.user)
        
        # Get basic stats
        total_files = File.objects.filter(owner=profile).count()
        total_folders = Folder.objects.filter(owner=profile).count()
        total_size = File.objects.filter(owner=profile).aggregate(
            total=Sum('file_size')
        )['total'] or 0
        
        # Recent activity
        recent_activity = ActivityLog.objects.filter(user=profile).order_by('-created_at')[:10]
        activity_serializer = ActivityLogSerializer(recent_activity, many=True)
        
        # Recent files
        recent_files = File.objects.filter(owner=profile).order_by('-created_at')[:5]
        files_serializer = FileSerializer(recent_files, many=True, context={'request': request})
        
        # Storage usage by type
        storage_by_type = File.objects.filter(owner=profile).values('mime_type').annotate(
            count=Count('id'),
            size=Sum('file_size')
        ).order_by('-size')[:5]
        
        return Response({
            'stats': {
                'total_files': total_files,
                'total_folders': total_folders,
                'total_size': total_size,
                'total_size_human': self.human_readable_size(total_size)
            },
            'recent_activity': activity_serializer.data,
            'recent_files': files_serializer.data,
            'storage_by_type': list(storage_by_type)
        })
    
    def human_readable_size(self, size_bytes):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

class SearchAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Global search across files and folders"""
        query = request.query_params.get('q', '').strip()
        if not query:
            return Response({'error': 'Search query required'}, status=status.HTTP_400_BAD_REQUEST)
        
        profile = Profile.objects.get(user=request.user)
        
        # Search files
        files = File.objects.filter(
            owner=profile,
            filename__icontains=query
        ).order_by('-created_at')[:20]
        
        # Search folders
        folders = Folder.objects.filter(
            owner=profile,
            name__icontains=query
        ).order_by('-created_at')[:20]
        
        files_serializer = FileSerializer(files, many=True, context={'request': request})
        folders_serializer = FolderSerializer(folders, many=True, context={'request': request})
        
        return Response({
            'query': query,
            'results': {
                'files': files_serializer.data,
                'folders': folders_serializer.data
            }
        })

# Additional utility views for file processing, analytics, etc.

class FileAnalyticsViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = FileAnalyticsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        return FileAnalytics.objects.filter(file__owner=profile).order_by('-access_date')

class ProcessingJobViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProcessingJobSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        profile = Profile.objects.get(user=self.request.user)
        return ProcessingJob.objects.filter(file__owner=profile).order_by('-created_at')

class ZeroXZeroUploadView(APIView):
    """
    Proxy view to upload files to 0x0.st and return the response
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    # FS limit (200MB)
    MAX_FILE_SIZE = 200 * 1024 * 1024
    
    def post(self, request):        
        if 'file' not in request.FILES:
            return Response({
                'error': 'No file provided'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        file_size = uploaded_file.size
        
        if file_size > self.MAX_FILE_SIZE:
            return Response({
                'error': 'File too large',
                'details': f'File size {self.human_readable_size(file_size)} exceeds maximum allowed size of {self.human_readable_size(self.MAX_FILE_SIZE)}',
                'max_size': self.human_readable_size(self.MAX_FILE_SIZE)
            }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        
        timeout_seconds = max(120, 120 + (file_size // (1024 * 1024)) * 30)
        
        max_retries = 2
        retry_count = 0
        
        client_timeout = httpx.Timeout(
            connect=30.0,
            read=timeout_seconds,
            write=timeout_seconds,
            pool=60.0
        )
        
        limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
        
        while retry_count <= max_retries:
            try:
                uploaded_file.seek(0)
                
                with httpx.Client(timeout=client_timeout, limits=limits) as client:
                    files = {
                        'file': (
                            uploaded_file.name,
                            uploaded_file,
                            uploaded_file.content_type
                        )
                    }
                    headers = {'User-Agent': 'FriendlyUploader'}
                    
                    response = client.post(
                        'https://0x0.st',
                        files=files,
                        headers=headers
                    )
                
                break
                
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as e:
                retry_count += 1
                if retry_count > max_retries:
                    raise e
                time.sleep(2 ** retry_count)
                continue

        try:
            profile = Profile.objects.get(user=request.user)
            ActivityLog.objects.create(
                user=profile,
                action_type='upload',
                resource_type='file',
                resource_name=uploaded_file.name,
                metadata={
                    'file_size': file_size,
                    'mime_type': uploaded_file.content_type,
                    'external_service': '0x0.st',
                    'status_code': response.status_code,
                    'timeout_used': timeout_seconds,
                    'retry_count': retry_count,
                    'max_retries': max_retries
                },
                ip_address=self.get_client_ip(),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return HttpResponse(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('Content-Type', 'text/plain')
            )
            
        except (httpx.TimeoutException, httpx.ReadTimeout, httpx.WriteTimeout):
            return Response({
                'error': 'Upload timeout',
                'details': f'Upload to 0x0.st timed out after {max_retries + 1} attempts. File size: {self.human_readable_size(file_size)}',
                'suggestion': 'Try uploading a smaller file or try again later',
                'timeout_used': timeout_seconds
            }, status=status.HTTP_504_GATEWAY_TIMEOUT)
        except (httpx.ConnectError, httpx.NetworkError):
            return Response({
                'error': 'Connection error',
                'details': f'Could not connect to 0x0.st after {max_retries + 1} attempts. The service might be temporarily unavailable.',
                'suggestion': 'Please try again in a few minutes'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        except httpx.HTTPError as e:
            return Response({
                'error': 'Failed to upload to external service',
                'details': str(e),
                'file_size': self.human_readable_size(file_size)
            }, status=status.HTTP_502_BAD_GATEWAY)
        except Exception as e:
            return Response({
                'error': 'Upload failed',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def human_readable_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def get_client_ip(self):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip
