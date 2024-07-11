# Shopping list printer
This project uses Remember the milk to create shopping lists you can easily edit on the go.
The items of the list are requested from a python webserver (~~I can't be bothered to create all the requests on the esp~~ this makes integrating any potential changes to the rememberthemilk api easy and without needing to leave the comfort of your pc).
The arduino prints the list on a thermal printer.

Now everyone can use a digital shopping list and the one "_I need a physical shopping list person_" can have a physical shopping list with the press of a button.

# Installation
## Webserver
- Apply for an api key (at the time of writing you can do that at https://www.rememberthemilk.com/services/api/keys.rtm)
- Use [the html file](authentication/index.html) to get your frob and auth token from remember the milk once you got the api key
- Put all of your api credentials into the docker compose
- You can change the shopping list name in the docker compose
- Generate the password hash and insert that. See [generating the password hash](#generating-the-password-hash)
- Deploy with `docker compose up -d` (or `docker-compose up -d` depending on your version)

### Generating the password hash
In the docker compose you find the variables `BASIC_AUTH_PASSWORD_HASH` and `BASIC_AUTH_PASSWORD`. You only need one.
You can directly input the password for the http basic auth into the docker file. If you do that, delete `BASIC_AUTH_PASSWORD_HASH`. This isn't good, as it stores your password in the docker compose.

Alternatively, use the following code to generate the scrypt password hash:
1. Install werkzeug
   - `pip install Werkzeug`
2. Enter a python console with
   - `python`
3. Import generate_password_hash
   - `from werkzeug.security import generate_password_hash`
4. Generate the password hash
   - `print(generate_password_hash('Your password goes here'))`

Insert the full string including `scrypt:` into the docker compose. Then delete `BASIC_AUTH_PASSWORD`.

## Arduino
- Change the server url in the arduino code
- Change the basic auth credentials in the arduino code

### Hardware

