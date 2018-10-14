import asyncio
import os

import requests
from flask import Flask, redirect, render_template, request, session
from patreon.utils import user_agent_string
from requests_oauthlib import OAuth2Session

import config
from database import PostgreClient
from token_check import TokenCheck

postgre_client = PostgreClient(
    user=config.db_user, host=config.db_host, database=config.db_data, password=config.db_pass
)
loop = asyncio.new_event_loop()

loop.run_until_complete(postgre_client.connect())

check_token = TokenCheck(postgre_client.get_pool(), loop)
check_token.run_renew()

app = Flask(__name__)

API_ENDPOINT = config.discord_api
CLIENT_ID = config.discord_id
CLIENT_SECRET = config.discord_secret
REDIRECT_URI = config.discord_redirect
TOKEN_URL = config.discord_token_url
API_BASE_URL = config.discord_api_url

app.config['SECRET_KEY'] = CLIENT_SECRET

if 'http://' in REDIRECT_URI:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'


def token_updater(token):
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=REDIRECT_URI,
        auto_refresh_kwargs={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/nopledge')
def nopledge():
    return render_template('nopledge.html')


@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/discord')
def discord_login():
    scope = request.args.get(
        'scope',
        'identify')
    discord = make_session(scope=scope.split(' '))
    authorization_url, state = discord.authorization_url(config.discord_authorize_url)
    session['oauth2_state'] = state
    return redirect(authorization_url)


@app.route('/discord/callback')
def discord_login_callback():
    if request.values.get('error'):
        return request.values['error']
    discord = make_session(state=session.get('oauth2_state'))
    token = discord.fetch_token(
        TOKEN_URL,
        client_secret=CLIENT_SECRET,
        authorization_response=request.url)
    session['discord_oauth2_token'] = token
    get_id = make_session(token=session.get('discord_oauth2_token'))
    user = get_id.get(API_BASE_URL + '/users/@me').json()
    session['user_id'] = user['id']

    return check_pledge()


@app.route('/patreon')
def patreon():
    patreon_auth = f'https://patreon.com/oauth2/authorize?response_type=code&client_id={config.patreon_id}&' \
                   f'redirect_uri={config.patreon_redirect}&scope=identity campaigns campaigns.members'
    return redirect(patreon_auth)


@app.route('/patreon/callback')
def patreon_callback():
    # Get TOKEN
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded"
    }

    params = {
        "code": request.args.get('code'),
        "grant_type": "authorization_code",
        "client_id": config.patreon_id,
        "client_secret": config.patreon_secret,
        "redirect_uri": config.patreon_redirect
    }

    token_request = requests.post("https://www.patreon.com/api/oauth2/token", headers=headers, data=params)

    session['access_token'] = token_request.json()['access_token']
    session['refresh_token'] = token_request.json()['refresh_token']

    # Get USER via TOKEN
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + session['access_token']
    }

    user_request = requests.get("https://www.patreon.com/api/oauth2/v2/identity?include=memberships", headers=headers)

    session['patreon_user_id'] = user_request.json()["data"]["id"]

    if len(user_request.json()["data"]["relationships"]["memberships"]["data"]) == 0:
        del session['access_token']
        return redirect('/nopledge')

    member_id = user_request.json()["data"]["relationships"]["memberships"]["data"][0]["id"]

    # Get MEMBER via ID
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + session['access_token']
    }

    member_request = requests.get("https://www.patreon.com/api/oauth2/v2/members/" + member_id +
                                  "?include=currently_entitled_tiers,campaign&fields%5Btier%5D=amount_cents",
                                  headers=headers)

    if member_request.json()["data"]["relationships"]["campaign"]["data"]["id"] != "1646586":
        del session['access_token']
        return redirect('/nopledge')

    if 100 <= member_request.json()["included"][1]["attributes"]["amount_cents"] <= 499:
        session['pledge'] = 1

    if member_request.json()["included"][1]["attributes"]["amount_cents"] >= 500:
        session['pledge'] = 2

    # Refresh TOKEN
    refresh_token()

    return check_pledge()


def check_pledge():
    if 'user_id' in session and 'patreon_user_id' in session and 'access_token' in session and \
            'refresh_token' in session and 'pledge' in session:
        loop.run_until_complete(
            set_entries(
                session['access_token'], session['refresh_token'], int(session['user_id']), session['patreon_user_id'],
                session['pledge']
            )
        )
        return redirect('/success')
    return redirect('/')


@asyncio.coroutine
async def set_entries(token, patreon_refresh_token, user_id, patreon_user_id, patreon_type):
    async with postgre_client.get_pool().acquire() as connection:
        check = await connection.prepare(
            'SELECT * FROM premium WHERE user_id = $1'
        )

        value_check = await check.fetchval(user_id)

        check_abuse = await connection.prepare(
            'SELECT * FROM premium WHERE patreon_id = $1'
        )

        value_check_abuse = await check_abuse.fetchval(patreon_user_id)

        if value_check is None and value_check_abuse is None:
            statement = await connection.prepare(
                'INSERT INTO premium (patreon_token, refresh_token, user_id, patreon_id, type) '
                'VALUES ($1, $2, $3, $4, $5)'
            )
        else:
            if check_abuse is None:
                statement = await connection.prepare(
                    'UPDATE premium SET patreon_token = $1, refresh_token = $2, user_id = $3, patreon_id = $4, '
                    'type = $5 WHERE user_id = $3'
                )
            else:
                statement = await connection.prepare(
                    'UPDATE premium SET patreon_token = $1, refresh_token = $2, user_id = $3, patreon_id = $4, '
                    'type = $5 '
                    'WHERE patreon_id = $4'
                )

        await statement.fetchval(token, patreon_refresh_token, user_id, patreon_user_id, patreon_type)


def refresh_token():
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded"
    }

    params = {
        "grant_type": "refresh_token",
        "refresh_token": session['refresh_token'],
        "client_id": config.patreon_id,
        "client_secret": config.patreon_secret
    }

    refresh_request = requests.post("https://www.patreon.com/api/oauth2/token", headers=headers, data=params)

    session['access_token'] = refresh_request.json()['access_token']
    session['refresh_token'] = refresh_request.json()['refresh_token']


if __name__ == '__main__':
    app.run()
