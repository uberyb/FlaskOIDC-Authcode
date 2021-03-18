from flask import Flask, redirect, render_template, request, url_for, session
import requests
import base64
import json
import re


# Variables for your OIDC app and org
url = "https://tobias.okta.com"
client_id = ""
client_secret = ""




def decode_base64(data, altchars=b'+/'):
    """Decode base64, padding being optional.
    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'='* (4 - missing_padding)
    return base64.b64decode(data, altchars)


app = Flask(__name__)
app.config['SECRET_KEY'] = "secretpassword" # this is just for flask sessions, you can ignore it

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/login")
# Construct the authorize url, here we need to supply redirect_uri, state, and nonce and then move the user to that location
def login():
    scope = "openid+profile"
    redirect_uri = "http://localhost/oidc-callback"
    state = "123"
    nonce = "56"
    auth_url = "/oauth2/v1/authorize?client_id={}&response_type=code&response_mode=query&scope={}&redirect_uri={}&state={}&nonce={}".format(client_id,scope,redirect_uri,state,nonce)
    return redirect(url+auth_url)

@app.route("/oidc-callback")
# User should be getting directed to this route with a code as a query parameter in the url. We then use the /token endpoint to retrieve an access token
def callback():
    if "code" in request.args:
        code = request.args.get('code')
        call_url = "/oauth2/v1/token"
        payload = {
            'grant_type': "authorization_code",
            'redirect_uri': 'http://localhost/oidc-callback',
            'code':code
        }

        authorization = "Basic " + base64.b64encode((client_id + ":" + client_secret).encode("ascii")).decode("ascii")

        headers = {
            'Accept': 'application/json',
            'Authorization': authorization, 
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(url + call_url, headers=headers, data = payload)
        session['access_token'] = response.json()['access_token']

        return redirect(url_for("profile"))
        

    return render_template(url_for("index"))

@app.route("/profile")
# We get the login name from the access token here
def profile():
    if session.get('access_token') is None:
        return redirect(url_for('index'))
    headers = {
        'Content-Type' : 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + session['access_token'].split(".")[1]
    }
    response = requests.get(url + "/api/v1/users/me", headers = headers, data={})
    print(response.text)
    a = json.loads(decode_base64(session['access_token'].split(".")[1].encode('ascii')).decode('ascii'))['sub']
    return render_template("profile.html", name = a)
    



if __name__ == "__main__":
    app.run(port=80, debug=True)
