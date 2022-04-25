import datetime

import jwt
from rest_framework.exceptions import AuthenticationFailed


def create_access_token(user_id):
    return jwt.encode({
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow(),
    }, 'access_secret_jwt_token_creation', algorithm='HS256')


def create_refresh_token(user_id):
    return jwt.encode({
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
    }, 'refresh_secret', algorithm='HS256')


def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret_jwt_token_creation', algorithms='HS256')
        return payload['user_id']
    except Exception as e:
        raise AuthenticationFailed('unauthenticated')


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')
        return payload['user_id']
    except Exception as e:
        print(e)
        raise AuthenticationFailed('unauthenticated')
