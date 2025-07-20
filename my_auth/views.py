import requests
import urllib.parse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponseRedirect, JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth import get_user_model
from .models import Profile, ShortLivedAuth
import secrets

User = get_user_model()

SLACK_CLIENT_ID     = settings.SLACK_CLIENT_ID
SLACK_CLIENT_SECRET = settings.SLACK_CLIENT_SECRET
REDIRECT_URI        = settings.REDIRECT_URI
HACK_CLUB_TEAM_ID   = settings.HACK_CLUB_TEAM_ID
FRONTEND_ENDPOINT   = settings.FRONTEND_ENDPOINT

@api_view(['GET'])
@permission_classes([AllowAny])
def slack_callback(request):
    code = request.GET.get('code')
    if not code:
        return Response({'error': 'No code provided'}, status=status.HTTP_400_BAD_REQUEST)

    token_res = requests.post('https://slack.com/api/openid.connect.token', data={
        'code': code,
        'client_id': SLACK_CLIENT_ID,
        'client_secret': SLACK_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
    })

    token_data = token_res.json()
    if not token_data.get('ok'):
        return Response({'error': token_data.get('error', 'Token request failed')}, status=status.HTTP_400_BAD_REQUEST)

    access_token = token_data.get('access_token')
    if not access_token:
        return Response({'error': 'No access token returned'}, status=status.HTTP_400_BAD_REQUEST)

    user_res = requests.get('https://slack.com/api/openid.connect.userInfo', headers={
        'Authorization': f'Bearer {access_token}'
    })

    user_data = user_res.json()
    if 'sub' not in user_data:
        return Response({'error': 'Invalid OpenID user info'}, status=status.HTTP_400_BAD_REQUEST)

    team_id = user_data.get('https://slack.com/team_id')
    if team_id != HACK_CLUB_TEAM_ID:
        return Response({'error': 'User is not in Hack Club Slack'}, status=status.HTTP_403_FORBIDDEN)

    email = user_data.get('email')
    name = user_data.get('name')
    picture = user_data.get('picture')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    user, _ = User.objects.get_or_create(
        email=email,
        defaults={
            'username': email,
            'first_name': name.split()[0] if name else '',
            'last_name': ' '.join(name.split()[1:]) if name and len(name.split()) > 1 else '',
        }
    )

    profile, _ = Profile.objects.get_or_create(user=user)
    profile.profile_picture = picture
    profile.save()

    refresh = RefreshToken.for_user(user)
    access = refresh.access_token

    auth_token = secrets.token_urlsafe(32)

    short_auth = ShortLivedAuth.objects.create(
        profile=profile,
        access=str(access),
        refresh=str(refresh),
        token=auth_token,
    )
    short_auth.save()

    # Redirect with short-lived auth ID
    if user.password and user.has_usable_password():
        redirect_url = f"{FRONTEND_ENDPOINT}/auth/auth_session?auth_code={auth_token}"
    else:
        redirect_url = f"{FRONTEND_ENDPOINT}/auth/set_new_password?auth_code={auth_token}"

    return HttpResponseRedirect(redirect_url)


@api_view(['POST'])
@permission_classes([AllowAny])
def temp_auth_code(request):
    auth_token = request.data.get('auth_code')
    if not auth_token:
        return Response({'error': 'Missing auth_code'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        short_auth = ShortLivedAuth.objects.get(token=auth_token)
    except ShortLivedAuth.DoesNotExist:
        return Response({'error': 'Invalid or expired auth_code'}, status=status.HTTP_404_NOT_FOUND)

    if short_auth.is_expired():
        short_auth.delete()
        return Response({'error': 'Auth code expired'}, status=status.HTTP_403_FORBIDDEN)

    user = short_auth.profile.user
    profile = short_auth.profile

    response = JsonResponse({
        'user': {
            'id': user.id,
            'name': user.get_full_name(),
            'email': user.email,
            'image': profile.profile_picture,
        }
    })

    response.set_cookie(
        key='access_token',
        value=short_auth.access,
        httponly=True,
        # secure=True,
        samesite=None,
        max_age=300
    )

    response.set_cookie(
        key='refresh_token',
        value=short_auth.refresh,
        httponly=True,
        # secure=True,
        samesite=None,
        max_age=86400
    )

    short_auth.delete()

    return response