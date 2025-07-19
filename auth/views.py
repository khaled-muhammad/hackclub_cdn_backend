import requests
from django.http import JsonResponse, HttpResponseRedirect

# Create your views here.

SLACK_CLIENT_ID = '2210535565.9217427988915'
SLACK_CLIENT_SECRET = '3f00d8fb92072b1674efb110adcbbd8f'
REDIRECT_URI = 'https://hackclub-cdn.khaled.hackclub.app/api/slack/callback'
HACK_CLUB_TEAM_ID = 'T0266FRGM'  # HC Slack workspace

def slack_callback(request):
    code = request.GET.get('code')
    if not code:
        return JsonResponse({'error': 'No code provided'}, status=400)

    token_res = requests.post('https://slack.com/api/oauth.v2.access', data={
        'code': code,
        'client_id': SLACK_CLIENT_ID,
        'client_secret': SLACK_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
    })

    token_data = token_res.json()
    if not token_data.get('ok'):
        return JsonResponse({'error': token_data.get('error')}, status=400)

    access_token = token_data['access_token']

    user_res = requests.get('https://slack.com/api/users.identity', headers={
        'Authorization': f'Bearer {access_token}'
    })

    user_data = user_res.json()
    if not user_data.get('ok'):
        return JsonResponse({'error': 'Could not get user info'}, status=400)

    if user_data['team']['id'] != HACK_CLUB_TEAM_ID:
        return JsonResponse({'error': 'Not a Hack Club user'}, status=403)

    user = user_data['user']

    return JsonResponse({
        'id': user['id'],
        'name': user['name'],
        'email': user['email'],
        'image': user['image_72'],
    })