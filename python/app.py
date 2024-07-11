import os

from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import rtm_helper

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    os.environ.get('BASIC_AUTH_USERNAME', ''): os.environ.get('BASIC_AUTH_PASSWORD_HASH', generate_password_hash(os.environ.get('BASIC_AUTH_PASSWORD', '')))
}


@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username


@app.route('/getShoppingListItems', methods=['GET'])
@auth.login_required
def index():
    return rtm_helper.get_items_to_buy()


if __name__ == '__main__':
    app.run(debug=True)
