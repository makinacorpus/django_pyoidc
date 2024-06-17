var keycloak = new Keycloak({
    realm: 'realm1',
    clientId: 'app1-front'
});

window.onload = async function () {
    try {
        var authenticated = await keycloak.init({
            onLoad: 'check-sso',
            checkLoginIframe: false
        })
    } catch (error) {
        var output = document.getElementById('message');
        output.innerHTML = '<span class="error">Failed to initialize connexion with Keycloak SSO</span>';
    }
    console.log(authenticated);
    if (authenticated) {
        userAuthenticated();
    } else {
        userNotAuthenticated();
    }
    document.getElementById('wrapper').style.display = 'block';
}

function userNotAuthenticated() {
    document.getElementById('anon').style.display = 'block';
    document.getElementById('authenticated').style.display = 'none';
}

function userAuthenticated() {
    document.getElementById('anon').style.display = 'none';
    document.getElementById('authenticated').style.display = 'block';
    document.getElementById('message').innerHTML = 'User: ' + keycloak.tokenParsed['preferred_username'];
    document.getElementById('debug').innerHTML = JSON.stringify(keycloak.tokenParsed);
}

async function request(endpoint) {
    var req = new XMLHttpRequest();
    var output = document.getElementById('message');
    req.open('GET', backendUrl + '/' + endpoint, true);
    req.setRequestHeader('Accept', 'application/json');

    if (keycloak.authenticated) {
        try {
            success = await keycloak.updateToken(30)
            output.innerHTML = '<span class="error">Sending request with Bearer</span>';
            req.setRequestHeader('Authorization', 'Bearer ' + keycloak.token);
        } catch (error) {
            output.innerHTML = '<span class="error">Failed to refresh user token</span>';
        };
    }

    req.onreadystatechange = function () {
        if (req.readyState == 4) {
            if (req.status == 200) {
                output.innerHTML = 'Message: ' + JSON.stringify(req.responseText);
            } else if (req.status == 403) {
                output.innerHTML = '<span class="error">Request Forbidden</span>';
            } else if (req.status == 0) {
                output.innerHTML = '<span class="error">Request failed</span>';
            } else {
                output.innerHTML = '<span class="error">' + req.status + ' ' + req.statusText + '</span>';
            }
        }
    };

    req.send();
}

keycloak.onAuthLogout = userNotAuthenticated;
