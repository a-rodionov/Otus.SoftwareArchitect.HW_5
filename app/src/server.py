import os
import json
import jwt

from flask import Flask, request, redirect
from flask_api import status
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Optional, Email
from sqlalchemy import create_engine
import urllib.parse

class EditUserForm(FlaskForm):
    firstName = StringField("firstName: ", validators=[DataRequired()])
    lastName = StringField("lastName: ", validators=[DataRequired()])
    phone = StringField("phone: ", validators=[DataRequired()])

class CreateUserForm(EditUserForm):
    username = StringField("username: ", validators=[DataRequired()])
    email = StringField("email: ", validators=[Email()])

app = Flask(__name__)
metrics = PrometheusMetrics(app)

ERROR_UNEXPECTED = 1
ERROR_INPUT_DATA = 2
ERROR_OBJECT_NOT_FOUND = 3

config = {
    'DATABASE_URI': os.environ.get('DATABASE_URI', ''),
    'HOSTNAME': os.environ['HOSTNAME'],
    'APP_NAME': os.environ.get('APP_NAME', 'no name'),
    'APP_URL_SCHEME': os.environ.get('APP_URL_SCHEME', ''),
    'APP_URL_HOST': os.environ.get('APP_URL_HOST', ''),
    'APP_URL_PATH': os.environ.get('APP_URL_PATH', ''),
    'AUTH_APP_URL_SCHEME': os.environ.get('AUTH_APP_URL_SCHEME', ''),
    'AUTH_APP_URL_HOST': os.environ.get('AUTH_APP_URL_HOST', ''),
    'AUTH_APP_URL_PATH': os.environ.get('AUTH_APP_URL_PATH', ''),
    'AUTH_PUB_KEY': b'-----BEGIN PUBLIC KEY-----\n' + os.environ['AUTH_PUB_KEY'].encode('ascii') + b'\n-----END PUBLIC KEY-----'
}

@app.route("/")
@app.route("/home")
def root():
    return 'Application \'' + config['APP_NAME'] + '\' from ' + config['HOSTNAME'] + '!'

@app.route("/health")
def health():
    return '{"status": "ok"}'

@app.route("/config")
def configuration():
    return json.dumps(config)

@app.route('/user', methods=['POST'])
def user_create():
    try:
        createUserForm = CreateUserForm(csrf_enabled=False)
        if createUserForm.validate():
            engine = create_engine(config['DATABASE_URI'], echo=True)
            with engine.connect() as connection:
                result = connection.execute('''insert into users (username, firstName, lastName, email, phone) values(%s, %s, %s, %s, %s) returning id''',
                                            (createUserForm.username.data,
                                             createUserForm.firstName.data,
                                             createUserForm.lastName.data,
                                             createUserForm.email.data.lower(),
                                             createUserForm.phone.data))
                return json.dumps({'objectId': result.scalar()})
        else:
            return json.dumps({'code': ERROR_INPUT_DATA, 'message': str(createUserForm.errors)})
    except Exception as exc:
        return json.dumps({'code': ERROR_UNEXPECTED, 'message': str(exc)})

@app.route('/user/<int:userId>', methods=['GET'])
def user_get(userId):
    try:
        decoded = jwt.decode(request.headers['X-Auth-Request-Access-Token'], config['AUTH_PUB_KEY'], options={'verify_aud': False})

        engine = create_engine(config['DATABASE_URI'], echo=True)
        rows = []
        with engine.connect() as connection:
            result = connection.execute('''select * from users where id=%s and email=%s''', userId, decoded['email'].lower())
            rows = [dict(r.items()) for r in result]
        return json.dumps(rows)
    except Exception as exc:
        return json.dumps({'code': ERROR_UNEXPECTED, 'message': str(exc)})

@app.route('/user/<int:userId>', methods=['DELETE'])
def user_delete(userId):
    try:
        decoded = jwt.decode(request.headers['X-Auth-Request-Access-Token'], config['AUTH_PUB_KEY'], options={'verify_aud': False})

        engine = create_engine(config['DATABASE_URI'], echo=True)
        with engine.connect() as connection:
            result = connection.execute('''delete from users where id=%s and email=%s returning id''', userId, decoded['email'].lower())
            if userId == result.scalar():
                return "User deleted", status.HTTP_204_NO_CONTENT
            else:
                return json.dumps({'code': ERROR_OBJECT_NOT_FOUND, 'message': 'Could not delete user with id = %d and email = %s, because it does not exist' % (userId, decoded['email'].lower())})
    except Exception as exc:
        return json.dumps({'code': ERROR_UNEXPECTED, 'message': str(exc)})

@app.route('/user/<int:userId>', methods=['PUT'])
def user_edit(userId):
    try:
        decoded = jwt.decode(request.headers['X-Auth-Request-Access-Token'], config['AUTH_PUB_KEY'], options={'verify_aud': False})

        editUserForm = EditUserForm(csrf_enabled=False)
        if editUserForm.validate():
            engine = create_engine(config['DATABASE_URI'], echo=True)
            with engine.connect() as connection:
                result = connection.execute('''update users set firstName=%s, lastName=%s, phone=%s where id=%s and email=%s returning id''',
                                            (editUserForm.firstName.data,
                                             editUserForm.lastName.data,
                                             editUserForm.phone.data,
                                             userId,
                                             decoded['email'].lower()))
                if userId == result.scalar():
                    return "User updated", status.HTTP_200_OK
                else:
                    return json.dumps({'code': ERROR_OBJECT_NOT_FOUND, 'message': 'Could not edit user with id = %d and email = %s, because it does not exist' % (userId, decoded['email'].lower())})
        else:
            return json.dumps({'code': ERROR_INPUT_DATA, 'message': str(editUserForm.errors)})
    except Exception as exc:
        return json.dumps({'code': ERROR_UNEXPECTED, 'message': str(exc)})

@app.route('/login')
def login():
    try:
        if 'X-Auth-Request-Access-Token' in request.headers:
            decoded = jwt.decode(request.headers['X-Auth-Request-Access-Token'], config['AUTH_PUB_KEY'], options={'verify_aud': False})
            return 'Hello, ' + decoded['preferred_username']
        else:
            return redirect(config["APP_URL_SCHEME"] + "://" + config["APP_URL_HOST"] + "/" + config["APP_URL_PATH"] + "/session", code=302)
    except Exception as exc:
        return json.dumps({'code': ERROR_UNEXPECTED, 'message': str(exc)})

@app.route('/logout')
def logout():
    try:
        if 'X-Auth-Request-Access-Token' in request.headers:
            return redirect(config["AUTH_APP_URL_SCHEME"] + "://" + config["AUTH_APP_URL_HOST"] + "/" + config["AUTH_APP_URL_PATH"] + "/sign_out?rd=" +
                            urllib.parse.quote_plus("/" + config["APP_URL_PATH"] + "/home"), code=302)
        else:
            return "User not logged in", status.HTTP_200_OK
    except Exception as exc:
        return json.dumps({'code': ERROR_UNEXPECTED, 'message': str(exc)})

@app.route('/session')
def session():

    if not 'X-Auth-Request-Access-Token' in request.headers:
        return "Not authenticated", status.HTTP_401_UNAUTHORIZED

    decoded = jwt.decode(request.headers['X-Auth-Request-Access-Token'], config['AUTH_PUB_KEY'], options={'verify_aud': False})

    data = {}
    data['preferred_username'] = decoded['preferred_username']
    data['given_name'] = decoded['given_name']
    data['family_name'] = decoded['family_name']
    data['email'] = decoded['email']

    if 'X-Auth-Request-Email' in request.headers:
        data['X-Auth-Request-Email'] = request.headers['X-Auth-Request-Email']
    if 'X-Auth-Request-Access-Token' in request.headers:
        data['X-Auth-Request-Access-Token'] = request.headers['X-Auth-Request-Access-Token']

    return data

if __name__ == "__main__":
    app.run(host='0.0.0.0',port='8000')