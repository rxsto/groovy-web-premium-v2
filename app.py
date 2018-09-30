import asyncio
import os

from token_check import TokenCheck
import patreon as patreonlib
from patreon.utils import user_agent_string
import requests

import config

from flask import Flask, session, redirect, request, render_template
from requests_oauthlib import OAuth2Session

from database import PostgreClient

postgre_client = PostgreClient(
    user=config.db_user, host=config.db_host, database=config.db_data, password=config.db_pass
)
loop = asyncio.new_event_loop()

loop.run_until_complete(postgre_client.connect())

check_token = TokenCheck(postgre_client.get_pool(), loop)

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
                   f'redirect_uri={config.patreon_redirect}'
    return redirect(patreon_auth)


@app.route('/patreon/callback')
def patreon_callback():
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

    r = requests.post(config.patreon_token_url, headers=headers, data=params)

    session['patreon_oauth2_token'] = r.json()['access_token']
    session['patreon_refresh_token'] = r.json()['refresh_token']

    api_client = patreonlib.API(session['patreon_oauth2_token'])
    user_response = api_client.fetch_user()
    user = user_response.data()

    session['patreon_user_id'] = user.id()

    pledges = user.relationship('pledges')
    pledge = pledges[0] if pledges and len(pledges) > 0 else None

    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded"
    }

    params = {
        "grant_type": "refresh_token",
        "refresh_token": session['patreon_refresh_token'],
        "client_id": config.patreon_id,
        "client_secret": config.patreon_secret
    }

    r = requests.post(config.patreon_token_url, headers=headers, data=params)

    session['access_token'] = r.json()['access_token']
    session['refresh_token'] = r.json()['refresh_token']

    if pledge is not None:
        if pledge['attributes']['declined_since'] is None:
            if 100 <= pledge['attributes']['amount_cents'] <= 499:
                session['pledge'] = 1
            elif 500 <= pledge['attributes']['amount_cents']:
                session['pledge'] = 2
            return check_pledge()
    else:
        del session['patreon_oauth2_token']
        return redirect('/nopledge')


def check_pledge():
    if 'user_id' in session and 'patreon_user_id' in session and 'access_token' in session and \
            'refresh_token' in session and 'pledge' in session:
        loop.run_until_complete(
            set_entries(
                session['access_token'], session['refresh_token'], session['user_id'], session['patreon_user_id'],
                session['pledge']
            )
        )
        return redirect('/success')
    return redirect('/')


@asyncio.coroutine
async def set_entries(token, refresh_token, user_id, patreon_user_id, patreon_type):
    async with postgre_client.get_pool().acquire() as connection:
        check = await connection.prepare(
            'SELECT * FROM premium WHERE user_id = $1'
        )

        await check.fetchval(user_id)

        check_abuse = await connection.prepare(
            'SELECT * FROM premium WHERE patreon_id = $1'
        )

        await check_abuse.fetchval(patreon_user_id)

        if check is None and check_abuse is None:
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

        await statement.fetchval(token, refresh_token, int(user_id), patreon_user_id, patreon_type)


if __name__ == '__main__':
    app.run()
