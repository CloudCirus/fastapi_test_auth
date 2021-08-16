import hmac
import hashlib
import base64
import json
from typing import Optional
from fastapi import FastAPI, Cookie, Body
from fastapi.responses import Response
from fake_db import USERS
from fake_settings import SECRET_KEY, PASSWORD_SALT


app = FastAPI()
secret_key = SECRET_KEY
pswd_salt = PASSWORD_SALT
users = USERS


def salt_my_password_baby(password: str, password_salt: str = pswd_salt) -> str:
    """возврашает salt хеш пароля"""
    _password = password + password_salt
    salt_password_bytes = hashlib.sha256(_password.encode())
    salt_password = salt_password_bytes.hexdigest()
    return salt_password


def verify_password(username: str, user_password: str) -> bool:
    """верифицирует пароль"""
    _inner_salt_password = salt_my_password_baby(user_password).lower()
    _salt_password_from_db = users.get(username)['password'].lower()
    return _inner_salt_password == _salt_password_from_db


def sign_cookie(data: str) -> None:
    """возвращает подписанные куки"""
    return hmac.new(
        secret_key.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_cookie(signed_str: str) -> Optional[str]:
    """возвращает decode имя из куки"""
    try:
        username_b64, sign = signed_str.split('.')
        username = base64.b64decode(username_b64.encode()).decode()
    except ValueError:
        return None
    if sign_cookie(username) == sign:
        return username


def index_response(index) -> Response:
    """пробует удалить невалидный куки и ответить индексом"""
    response = Response(index, media_type='text/html')
    try:
        response.delete_cookie(key='username')
    except Exception as ex:
        print(ex)
    return response


def get_index_html(path: str) -> str:
    """забирает шаблон"""
    with open(path, 'r') as f:
        index = f.read()
        return index


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    index = index_response(get_index_html('templates/index.html'))

    if not username:
        return index
    valid_username = get_username_from_signed_cookie(username)
    if not valid_username or None:
        return index
    try:
        users[valid_username]
    except KeyError:
        index
    return Response(
        f'Привет: {valid_username} <br/> Твой баланс: {users.get(valid_username)["balance"]}', media_type='text/html')


@app.post("/login")
def proccess_login_page(data: dict = Body(...)):
    username = data.get('username')
    password = data.get('password')
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                'success': False,
                'message': 'я вас не знаю!'
            }),
            media_type='application/json')
    response = Response(
        json.dumps({
            'success': True,
            'message': f'Привет: {username} <br/> Твой баланс: {user["balance"]}'
        }),
        media_type='application/json')
    username_signed = f'{base64.b64encode(username.encode()).decode()}.{sign_cookie(username)}'
    response.set_cookie(key='username', value=username_signed)
    return response
