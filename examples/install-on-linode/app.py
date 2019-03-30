import re
from flask import Flask, redirect, request, render_template, session, send_from_directory
from linode_api4 import (LinodeClient, LinodeLoginClient, StackScript, Image, Region,
                         Type, OAuthScopes)
import config

app=Flask(__name__)
app.config['SECRET_KEY'] = config.secret_key

def get_login_client():
    return LinodeLoginClient(config.client_id, config.client_secret)

@app.route('/')
def index():
    client = LinodeClient('no-token')
    types = client.linode.types(Type.label.contains("Linode"))
    regions = client.regions()
    stackscript = StackScript(client, config.stackscript_id)
    return render_template('configure.html',  
        types=types,
        regions=regions,
        application_name=config.application_name,
        stackscript=stackscript
    )

@app.route('/', methods=["POST"])
def start_auth():
    login_client = get_login_client()
    session['dc'] = request.form['region']
    session['distro'] = request.form['distribution']
    session['type'] = request.form['type']
    session['RUNCMD'] = request.form['RUNCMD']
    return redirect(login_client.generate_login_url(scopes=OAuthScopes.Linodes.create))

@app.route('/auth_callback')
def auth_callback():
    code = request.args.get('code')
    login_client = get_login_client()
    token, scopes, _, _ = login_client.finish_oauth(code)

    # ensure we have sufficient scopes
    if not OAuthScopes.Linodes.create in scopes:
        return render_template('error.html', error='Insufficient scopes granted to deploy {}'\
                .format(config.application_name))

    (linode, password) = make_instance(token, session['type'], session['dc'], 
                         session['distro'], session['RUNCMD'])

    get_login_client().expire_token(token)
    return render_template('success.html',
        password=password,
        linode=linode,
        application_name=config.application_name
    )

def make_instance(token, type_id, region_id, distribution_id, runcmd):
    client = LinodeClient('{}'.format(token))
    stackscript = StackScript(client, config.stackscript_id)
    (linode, password) = client.linode.instance_create(type_id, region_id,
            group=config.application_name,
            image=distribution_id, stackscript=stackscript.id,
            stackscript_data = {
                "PUBKEY" : "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDfP0oZ/G7hNhD0r8e78fDqaQMIsa1kiFckGlWco8RKlv4qoz50EypAW2BTmzvEwq0bVkrLYV9P2wr2F0H2YISuHppth9rxUQ84R3ePae6B6grQK867aCif1x+SDx2mqR7+lDlk0OdzlTxOTVLIISI6n7JOltfvwvWLlA1W2SEJybh/D50+DDzzsDEWpLNWojJmFI3LhBL1T6OiL0flckoxq+56u2K6BHF0wkBNRmBh1iEpGhGSycg26qhg6xBWmvEbpiNmZZDUv+ddbjFC4lMnmT/MvudDqXktgM6XiZhsERXv06ijBtDb8conty8zxsPrXWcFGABThD9l2e6pjpQAZTpseE13gp4ox/IV1SuJDa6THOgRrlaN1QEC6mSbVbuHROJKcDM9oFmAxlj23xA6XKxE878s9vVbvhHNiLJTccfHkdNxgNn1KZho44DBOYwaOgc70o4dvi6j02bLNgsEHNnGyZTQ3JQr062LugULXhGEArjNqCBFc8K953pcKW9r2T+KsayilDBRuV2SkBuDk8Z03fZn03ZCLJ3VqVVJtbbxDAij347932ecUZw5EW6JamPuPKncO/9+ut3EsF1HRy5gZ8ZRRcLB5b05yzhvdlyvjJ9fjnJDVToo4V3fMwQZkHhaEN/QwkWHxxJuUbUMaUZp6k+U6xRK/ZP9jKcIqw== hross@Linodes-MacBook-Pro.local",
                "RUNCMD" : runcmd,
                "SKIP" : "yes"
                }
            )
    
    if not linode:
        raise RuntimeError("it didn't work")
    return linode, password

if __name__ == '__main__':
    app.debug=True
    app.run(host='0.0.0.0',port='443',ssl_context='adhoc')
