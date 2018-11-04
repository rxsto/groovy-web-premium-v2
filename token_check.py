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
        print(f'Starting to refresh all entries ...')
        async with self.pool.acquire() as connection:
            print(f'Connected to database!')
            users = await connection.fetch('SELECT * FROM premium')
            print(f'Received all entries!')
            for user in range(0, len(users)):
                if users[user]['check'] is True:
                    print(f'Refreshing entries for user with ID {users[user]["user_id"]} ...')

                    # Get UserResource via Access-Token
                    headers = {
                        "User-Agent": user_agent_string(),
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": "Bearer " + users[user]['patreon_token']
                    }

                    user_request = requests.get(config.patreon_api_base_url + "/oauth2/v2/identity?include=memberships",
                                                headers=headers)

                    patreon_user = user_request.json()["data"]

                    if len(patreon_user["relationships"]["memberships"]["data"]) == 0:
                        statement = await connection.prepare(
                            'DELETE FROM premium WHERE user_id = $1'
                        )

                        await statement.fetchval(users[user]['user_id'])
                        print(f'Deleted entries for user with ID {users[user]["user_id"]}!')
                        return

                    patreon_id = patreon_user["id"]

                    member_id = patreon_user["relationships"]["memberships"]["data"][0]["id"]

                    # Get MemberResource via MemberID from UserRequest
                    headers = {
                        "User-Agent": user_agent_string(),
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": "Bearer " + users[user]['patreon_token']
                    }

                    member_request = requests.get(
                        config.patreon_api_base_url + "/oauth2/v2/members/" + member_id +
                        "?include=currently_entitled_tiers,campaign&fields%5Btier%5D=amount_cents&fields%5Bmember%5D=last_charge_date,last_charge_status,lifetime_support_cents,patron_status,currently_entitled_amount_cents,will_pay_amount_cents",
                        headers=headers
                    )

                    member = member_request.json()["data"]

                    if member["attributes"]["last_charge_status"] == "Pending":
                        print(f'Pending entries for user with ID {users[user]["user_id"]}!')
                        return

                    if member["attributes"]["last_charge_status"] != "Paid" or member["attributes"][
                        "lifetime_support_cents"] == 0 or \
                            member["attributes"]["patron_status"] != "active_patron":
                        statement = await connection.prepare(
                            'DELETE FROM premium WHERE user_id = $1'
                        )
                        print(f'Deleted entries for user with ID {users[user]["user_id"]}!')

                        await statement.fetchval(users[user]['user_id'])
                        return

                    amount = member["attributes"]["currently_entitled_amount_cents"]

                    if amount == 100:
                        donation_type = 1
                    elif amount == 500:
                        donation_type = 2
                    elif amount > 100:
                        statement = await connection.prepare(
                            'DELETE FROM premium WHERE user_id = $1'
                        )
                        print(f'Deleted entries for user with ID {users[user]["user_id"]} because no valid pledge!')

                        await statement.fetchval(users[user]['user_id'])
                        return
                    else:
                        statement = await connection.prepare(
                            'DELETE FROM premium WHERE user_id = $1'
                        )
                        print(f'Deleted entries for user with ID {users[user]["user_id"]}!')

                        await statement.fetchval(users[user]['user_id'])
                        return

                    # Refresh Tokens
                    headers = {
                        "User-Agent": user_agent_string(),
                        "Content-Type": "application/x-www-form-urlencoded"
                    }

                    params = {
                        "grant_type": "refresh_token",
                        "refresh_token": users[user]['refresh_token'],
                        "client_id": config.patreon_client_id,
                        "client_secret": config.patreon_client_secret
                    }

                    refresh_request = requests.post(config.patreon_api_base_url + "/oauth2/token", headers=headers,
                                                    data=params)

                    token = refresh_request.json()['access_token']
                    refresh = refresh_request.json()['refresh_token']

                    # Update Entry
                    statement = await connection.prepare(
                        'UPDATE premium SET patreon_token = $1, refresh_token = $2, type = $3 WHERE patreon_id = $4'
                    )

                    await statement.fetchval(token, refresh, donation_type, patreon_id)
                    print(f'Updating entries for user with ID {users[user]["user_id"]} ...')

                    # Execute every 12h
                    Timer(60 * 60 * 12, self.run_renew).start()
