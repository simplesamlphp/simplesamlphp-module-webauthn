// the following two functions are taken from https://stackoverflow.com/questions/16363419/how-to-get-binary-string-from-arraybuffer

function BinaryToString(binary)
{
    var error;

    try {
        return decodeURIComponent(escape(binary));
    } catch (_error) {
        error = _error;
        if (error instanceof URIError) {
            return binary;
        } else {
            throw error;
        }
    }
}

function ArrayBufferToString(buffer)
{
    return BinaryToString(String.fromCharCode.apply(null, Array.prototype.slice.apply(new Uint8Array(buffer))));
}

function registrationButtonClick()
{
    navigator.credentials.create(publicKeyCredentialCreationOptions)
    .then((cred) => {
        console.log('NEW CREDENTIAL', cred);
        document.getElementById('resp').value = cred.id;
        var enc = new TextDecoder('utf-8');
        document.getElementById('data').value = enc.decode(cred.response.clientDataJSON);
        document.getElementById('attobj').value = btoa(ArrayBufferToString(cred.response.attestationObject));
        document.getElementById('type').value = cred.response.type;
        document.forms['regform'].submit();
    })
    .then((assertion) => {
        console.log('ASSERTION', assertion);
    })
    .catch((err) => {
        alert("Something went wrong. It is possible that you are trying to use an invalid token.")
        console.log('ERROR', err);
    });
}

function authButtonClick()
{
    navigator.credentials.get(publicKeyCredentialRequestOptions)
    .then((cred) => {
        console.log('AUTH', cred);
        document.getElementById('resp').value = cred.id;
        var enc = new TextDecoder('utf-8');
        document.getElementById('data_raw_b64').value = btoa(ArrayBufferToString(cred.response.clientDataJSON));
        document.getElementById('data').value = enc.decode(cred.response.clientDataJSON);
        document.getElementById('authdata').value = btoa(ArrayBufferToString(cred.response.authenticatorData));
        document.getElementById('sigdata').value = btoa(ArrayBufferToString(cred.response.signature));
        document.getElementById('type').value = cred.response.type;
        document.forms['authform'].submit();
    })
    .then((assertion) => {
        console.log('ASSERTION', assertion);
    })
    .catch((err) => {
        console.log('ERROR', err);
    });
}

var frontendData = JSON.parse(document.getElementById('frontendData').getAttribute('content'));
var publicKeyCredentialCreationOptions = {
    publicKey: {
        challenge: new Uint8Array(frontendData['challengeEncoded']).buffer,
        rp: {
            name: frontendData['state']['Source']['entityid'],
            id: frontendData['state']['FIDO2Scope'],
        },
        user: {
            id: new Uint8Array(frontendData['usernameEncoded']).buffer,
            name: frontendData['state']['FIDO2Username'],
            displayName: frontendData['state']['FIDO2Displayname'],
        },
        pubKeyCredParams: [{alg: -7, type: 'public-key'}],
        authenticatorSelection: {
            userVerification: "discouraged"
        },
        timeout: 60000,
        attestation: frontendData['attestation'],
    }
};

const publicKeyCredentialRequestOptions = {
    publicKey: {
        challenge: new Uint8Array(frontendData['challengeEncoded']).buffer,
        rpId: frontendData['state']['FIDO2Scope'],
        timeout: 60000,
        allowCredentials: frontendData['credentialIdEncoded'].map((oneId) => {
            return {id: new Uint8Array(oneId).buffer, type: 'public-key'};
        }),
    }
};


window.addEventListener('DOMContentLoaded', () => {
    let regform = document.getElementById('regform');
    if (regform !== null) {
        document.getElementById('regformSubmit').addEventListener('click', registrationButtonClick);
        regform.addEventListener('submit', () => false);
        document.getElementById('tokenname').addEventListener('keydown', (event) => {
            if (event.keyCode == 13) {
                return false;
            }
        });
    }
    let authform = document.getElementById('authform');
    if (authform !== null) {
        document.getElementById('authformSubmit').addEventListener('click', authButtonClick);
        authform.addEventListener('submit', () => false);
    }
});
