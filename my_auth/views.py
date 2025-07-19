import requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

# Load environment variables

# Read from environment

SLACK_CLIENT_ID     = settings.SLACK_CLIENT_ID
SLACK_CLIENT_SECRET = settings.SLACK_CLIENT_SECRET
REDIRECT_URI        = settings.REDIRECT_URI
HACK_CLUB_TEAM_ID   = settings.HACK_CLUB_TEAM_ID

@api_view(['GET'])
@permission_classes([AllowAny])
def slack_callback(request):
    code = request.GET.get('code')
    if not code:
        return Response({'error': 'No code provided'}, status=status.HTTP_400_BAD_REQUEST)

    # Step 1: Exchange code for token
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

    # Step 2: Get user info
    user_res = requests.get('https://slack.com/api/openid.connect.userInfo', headers={
        'Authorization': f'Bearer {access_token}'
    })

    user_data = user_res.json()

    if 'sub' not in user_data:
        return Response({'error': 'Invalid OpenID user info'}, status=status.HTTP_400_BAD_REQUEST)

    # Step 3: Validate team ID
    team_id = user_data.get('https://slack.com/team_id')
    if team_id != HACK_CLUB_TEAM_ID:
        return Response({'error': 'User is not in Hack Club Slack'}, status=status.HTTP_403_FORBIDDEN)

    # Step 4: Prepare user data
    email = user_data.get('email')
    name = user_data.get('name')
    picture = user_data.get('picture')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            'username': email,
            'first_name': name.split()[0] if name else '',
            'last_name': ' '.join(name.split()[1:]) if name and len(name.split()) > 1 else '',
        }
    )

    # Step 5: Generate JWT
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token

    return Response({
        'access': str(access),
        'refresh': str(refresh),
        'profile': {
            'id': user.id,
            'name': user.get_full_name(),
            'email': user.email,
            'image': picture,
            'team_id': team_id,
        },
        'created': created,
    })