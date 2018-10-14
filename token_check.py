from threading import Timer

import requests
from patreon.utils import user_agent_string

import config


class TokenCheck:
    def __init__(self, pool, loop):
        self.pool = pool
        self.loop = loop

    def run_renew(self):
        self.loop.run_until_complete(
            self.renew()
        )

    async def renew(self):
        async with self.pool.acquire() as connection:
            users = await connection.fetch('SELECT * FROM premium')
            for user in range(1, len(users)):
                if users[user]['check'] is True:
                    # Get USER via TOKEN
                    headers = {
                        "User-Agent": user_agent_string(),
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": "Bearer " + users[user]['patreon_token']
                    }

                    user_request = requests.get("https://www.patreon.com/api/oauth2/v2/identity?include=memberships",
                                                headers=headers)

                    patreon_id = user_request.json()["data"]["id"]
                    member_id = user_request.json()["data"]["relationships"]["memberships"]["data"][0]["id"]

                    # Get MEMBER via ID
                    headers = {
                        "User-Agent": user_agent_string(),
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": "Bearer " + users[user]['patreon_token']
                    }

                    member_request = requests.get("https://www.patreon.com/api/oauth2/v2/members/" + member_id +
                                                  "?include=currently_entitled_tiers,campaign&fields%5Btier%5D=amount_cents",
                                                  headers=headers)

                    patreon_type = None

                    if member_request.json()["data"]["relationships"]["campaign"]["data"]["id"] == "2120599":
                        if 100 <= member_request.json()["included"][1]["attributes"]["amount_cents"] <= 499:
                            patreon_type = 1

                        if member_request.json()["included"][1]["attributes"]["amount_cents"] >= 500:
                            patreon_type = 2

                    if patreon_type is None:
                        statement = await connection.prepare(
                            'DELETE FROM premium WHERE user_id = $1'
                        )

                        await statement.fetchval(users[user]['user_id'])
                        break

                    headers = {
                        "User-Agent": user_agent_string(),
                        "Content-Type": "application/x-www-form-urlencoded"
                    }

                    params = {
                        "grant_type": "refresh_token",
                        "refresh_token": users[user]['refresh_token'],
                        "client_id": config.patreon_id,
                        "client_secret": config.patreon_secret
                    }

                    r = requests.post("https://www.patreon.com/api/oauth2/token", headers=headers, data=params)

                    token = r.json()['access_token']
                    refresh_token = r.json()['refresh_token']

                    statement = await connection.prepare(
                        'UPDATE premium SET patreon_token = $1, refresh_token = $2, type = $3 WHERE patreon_id = $4'
                    )

                    await statement.fetchval(token, refresh_token, patreon_type, patreon_id)

                    Timer(60 * 60 * 12, self.run_renew).start()
