from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'folders', views.FolderViewSet, basename='folders')
router.register(r'files', views.FileViewSet, basename='files')
router.register(r'shares', views.ShareViewSet, basename='shares')
router.register(r'activity', views.ActivityLogViewSet, basename='activity')
router.register(r'trash', views.TrashViewSet, basename='trash')
router.register(r'analytics', views.FileAnalyticsViewSet, basename='analytics')
router.register(r'processing', views.ProcessingJobViewSet, basename='processing')

app_name = 'cdn'

urlpatterns = [
    path('api/cdn/', include(router.urls)),
    
    path('api/cdn/dashboard/', views.DashboardAPIView.as_view(), name='dashboard'),
    path('api/cdn/search/', views.SearchAPIView.as_view(), name='search'),
    path('api/cdn/upload-0x0/', views.ZeroXZeroUploadView.as_view(), name='upload_0x0'),
]