# cd python/src && python AccessTokenTest.py
import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
import AccessToken

app_id = "123456781234567812345678"
app_key = "app key"
room_id = "new room"
user_id = "new user id"

token = AccessToken.AccessToken(app_id, app_key, room_id, user_id)
token.add_privilege(AccessToken.PrivSubscribeStream, 0)
token.add_privilege(AccessToken.PrivPublishStream, int(time.time()) + 3600)
token.expire_time(int(time.time()) + 3600)

s = token.serialize()

print(s)

t = AccessToken.parse(s)

print(t.verify(app_key))
