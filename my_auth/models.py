import secrets
from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model

User = get_user_model()
# Create your models here.

class Profile(models.Model):
    user            = models.ForeignKey(User, on_delete=models.CASCADE)
    profile_picture = models.URLField(User, null=True, blank=True)

    def __str__(self):
        return self.user.username

class ShortLivedAuth(models.Model):
    profile    = models.ForeignKey('Profile', on_delete=models.CASCADE)
    token      = models.CharField(max_length=64, unique=True)
    access     = models.CharField(max_length=255)
    refresh    = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)