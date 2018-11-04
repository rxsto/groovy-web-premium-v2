import asyncio
import os
import logging

import requests
from flask import Flask, redirect, render_template, request, session
from patreon.utils import user_agent_string
from requests_oauthlib import OAuth2Session

import config
from database import PostgreClient
from token_check import TokenCheck

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

postgre_client = PostgreClient(
    user=config.database_username, host=config.database_hostname, database=config.database_database,
    password=config.database_password
)
loop = asyncio.new_event_loop()

loop.run_until_complete(postgre_client.connect())

check_token = TokenCheck(postgre_client.get_pool(), loop)
check_token.run_renew()

app = Flask(__name__)

if __name__ != "__main__":
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

DISCORD_API_BASE_URL = "https://discordapp.com/api"

app.config['SECRET_KEY'] = config.discord_client_secret

gunicorn_logger = logging.getLogger("gunicorn.error")
app.logger.handlers = gunicorn_logger.handlers


def token_updater(token):
    # Initialize token_updater
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    # Make new OAuth2Session
    return OAuth2Session(
        client_id=config.discord_client_id,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=config.discord_redirect_url,
        auto_refresh_kwargs={
            'client_id': config.discord_client_id,
            'client_secret': config.discord_client_secret,
        },
        auto_refresh_url=config.discord_api_base_url + "/oauth2/token",
        token_updater=token_updater
    )


@app.route('/')
def home():
    # Render Index-Site
    return render_template('index.html')


@app.route('/nopledge')
def nopledge():
    # Render NoPledge-Site
    return render_template('nopledge.html')


@app.route('/success')
def success():
    # Render Success-Site
    return render_template('success.html')


@app.route('/custom')
def custom():
    # Render Success-Site
    return render_template('custom.html')


@app.route('/pending')
def pending():
    # Render Success-Site
    return render_template('pending.html')


@app.route('/discord')
def discord_login():
    # Get Scopes
    scope = request.args.get(
        'scope',
        'identify'
    )

    # Make new Session
    discord = make_session(scope=scope.split(' '))
    authorization_url, state = discord.authorization_url(config.discord_api_base_url + "/oauth2/authorize")

    # Set OAuth2-state in Session
    session['oauth2_state'] = state

    # Redirect to Discord-Authorization-URL
    return redirect(authorization_url)


@app.route('/discord/callback')
def discord_login_callback():
    # If error occures return it
    if request.values.get('error'):
        return request.values['error']

    # Make new Session
    discord = make_session(state=session.get('oauth2_state'))

    # Fetch token for authorization
    token = discord.fetch_token(
        config.discord_api_base_url + "/oauth2/token",
        client_secret=config.discord_client_secret,
        authorization_response=request.url
    )

    # Save token in session
    session['discord_oauth2_token'] = token

    # Get UserID via token
    get_id = make_session(token=session.get('discord_oauth2_token'))
    user = get_id.get(config.discord_api_base_url + '/users/@me').json()

    # Save UserID in Session
    session['user_id'] = user['id']
    return check_pledge()


@app.route('/patreon')
def patreon():
    # Redirect to Patreon-Authorization-URL
    return redirect(config.patreon_authorization_url)


@app.route('/patreon/callback')
def patreon_callback():
    # Get Access-Token via OAuth2
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded"
    }

    params = {
        "code": request.args.get('code'),
        "grant_type": "authorization_code",
        "client_id": config.patreon_client_id,
        "client_secret": config.patreon_client_secret,
        "redirect_uri": config.patreon_redirect_url
    }

    token_request = requests.post(config.patreon_api_base_url + "/oauth2/token", headers=headers, data=params)

    session['access_token'] = token_request.json()['access_token']
    session['refresh_token'] = token_request.json()['refresh_token']

    # Get UserResource via Access-Token
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + session['access_token']
    }

    user_request = requests.get(config.patreon_api_base_url + "/oauth2/v2/identity?include=memberships",
                                headers=headers)

    user = user_request.json()["data"]

    if len(user["relationships"]["memberships"]["data"]) == 0:
        return redirect('/nopledge')

    session['patreon_user_id'] = user_request.json()["data"]["id"]

    member_id = user["relationships"]["memberships"]["data"][0]["id"]

    # Get MemberResource via MemberID from UserRequest
    headers = {
        "User-Agent": user_agent_string(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + session['access_token']
    }

    member_request = requests.get(
        config.patreon_api_base_url + "/oauth2/v2/members/" + member_id +
        "?include=currently_entitled_tiers,campaign&fields%5Btier%5D=amount_cents&fields%5Bmember%5D=last_charge_date,last_charge_status,lifetime_support_cents,patron_status,currently_entitled_amount_cents,will_pay_amount_cents",
        headers=headers
    )

    member = member_request.json()["data"]

    if member["attributes"]["last_charge_status"] == "Pending":
        return redirect("/pending")

    if member["attributes"]["last_charge_status"] != "Paid" or member["attributes"]["lifetime_support_cents"] == 0 or \
            member["attributes"]["patron_status"] != "active_patron":
        return redirect("/nopledge")

    amount = member["attributes"]["currently_entitled_amount_cents"]

    if amount == 100:
        app.logger.info("Somebody authorized with an amount of " + str(amount) + " cents!")
        session['pledge'] = 1
    elif amount == 500:
        app.logger.info("Somebody authorized with an amount of " + str(amount) + " cents!")
        session['pledge'] = 2
    elif amount > 100:
        app.logger.warn("Somebody wanted to authorize with a custom pledge!")
        app.logger.warn(member)
        return redirect("/custom")
    else:
        return redirect("/nopledge")

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
        "client_id": config.patreon_client_id,
        "client_secret": config.patreon_client_secret
    }

    refresh_request = requests.post("https://www.patreon.com/api/oauth2/token", headers=headers, data=params)

    session['access_token'] = refresh_request.json()['access_token']
    session['refresh_token'] = refresh_request.json()['refresh_token']


if __name__ == '__main__':
    app.run()
