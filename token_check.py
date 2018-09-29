from threading import Timer

import requests
import patreon as patreonlib
from patreon.utils import user_agent_string

import config


class TokenCheck:
    def __init__(self, pool, loop):
        self.pool = pool
        self.loop = loop

    def run_renew(self):
        self.loop.create_task(
            self.renew()
        )

    async def renew(self):
        async with self.pool.acquire() as connection:
            for user in await connection.fetch('SELECT * FROM premium'):
                if user['check'] is False:
                    return
                api_client = patreonlib.API(user['patreon_token'])
                user_response = api_client.fetch_user()
                patreon_user = user_response.data()
                pledges = patreon_user.relationship('pledges')
                pledge = pledges[0] if pledges and len(pledges) > 0 else None

                patreon_type = None

                if pledge is not None:
                    if pledge['attributes']['declined_since'] is None:
                        if pledge['attributes']['amount_cents'] == 100:
                            patreon_type = 1
                        elif pledge['attributes']['amount_cents'] == 500:
                            patreon_type = 2
                else:
                    statement = await connection.prepare(
                        'DELETE FROM premium WHERE user_id = $1'
                    )

                    return await statement.fetchval(user['user_id'])

                headers = {
                    "User-Agent": user_agent_string(),
                    "Content-Type": "application/x-www-form-urlencoded"
                }

                params = {
                    "grant_type": "refresh_token",
                    "refresh_token": user['refresh_token'],
                    "client_id": config.patreon_id,
                    "client_secret": config.patreon_secret
                }

                r = requests.post(config.patreon_token_url, headers=headers, data=params)

                token = r.json()['access_token']
                refresh_token = r.json()['refresh_token']

                statement = await connection.prepare(
                    'UPDATE premium SET patreon_token = $1, refresh_token = $2, type = $3'
                )

                await statement.fetchval(token, refresh_token,  patreon_type)

                Timer(60 * 60 * 24, self.run_renew).start()
