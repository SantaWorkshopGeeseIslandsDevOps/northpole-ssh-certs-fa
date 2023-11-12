"""Azure Function App to create SSH certificates."""
import base64
import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Tuple

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from sshkey_tools.cert import CertificateFields, SSHCertificate
from sshkey_tools.keys import PrivateKey, PublicKey

DEFAULT_PRINCIPAL = os.environ['DEFAULT_PRINCIPAL']
KEY_VAULT_URL = os.environ['KEY_VAULT_URL']
CA_KEY_SECRET_NAME = os.environ['CA_KEY_SECRET_NAME']

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)


class ValidationError(BaseException):
    """Validation error."""


def parse_input(data) -> Tuple[PublicKey, str]:
    """Parse and validate input parameters."""
    ssh_pub_key = data.get("ssh_pub_key")

    if not ssh_pub_key:
        raise ValidationError("ssh_pub_key field is required.")

    if not isinstance(ssh_pub_key, str):
        raise ValidationError("ssh_pub_key is not a string.")

    ssh_pub_key = ssh_pub_key.strip()
    logging.info("SSH public key: %s", ssh_pub_key)

    if not (ssh_pub_key.lower().startswith("ssh-rsa") or ssh_pub_key.lower().startswith("ssh-ed25519")):
        raise ValidationError("ssh_pub_key is not an RSA or ED25519 SSH public key.")

    principal = data.get("principal", DEFAULT_PRINCIPAL)

    if not isinstance(principal, str):
        raise ValidationError("principal is not a string.")

    principal = principal.strip()
    logging.info("Principal: %s", principal)

    if not principal.isalpha():
        raise ValidationError("principal contains invalid characters.")

    try:
        return PublicKey.from_string(ssh_pub_key), principal
    except ValueError as err:
        raise ValidationError("ssh_pub_key is not a valid SSH public key.") from err


def get_form() -> str:
    """Get HTML form."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Request SSH Certificate</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #0093E9 0%, #80D0C7 100%);
            margin: 0;
            padding: 20px;
            background-attachment: fixed;
            background-size: cover;
            text-align: center;
        }
        .chatnpt_ad {
            background-color: #f9f2df;
            padding: 2px;
            border-radius: 10px;
            border: 4px solid #c0a080;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 680px;
            margin-left: auto;
            margin-right: auto;
            margin-bottom: 30px;
            color: #222;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .chatnpt_ad .emoji { font-size: 4rem; }
        .chatnpt_ad .message { padding: 0 1rem; }
        .chatnpt_ad p {
            color: #222;
            font-size: 1.2rem;
            margin: 0px;
        }
        .chatnpt_ad .tagline {
            color: #ff5733;
        }
        @keyframes blinker {
            50% {
                opacity: 0;
            }
        }
        .chatnpt_ad strong {
            color: #0077cc;
            animation: blinker 1.5s linear infinite;
        }
        .container {
            background-color: rgba(255, 255, 255, 0.8);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, .2);
            text-align: left;
        }
        .container h1 {
            color: #003366;
            text-align: center;
            margin-bottom: 20px;
        }
        #ssh_pub_key_textarea {
            width: 100%;
            box-sizing: border-box;
            resize: vertical;
            margin-bottom: 10px;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
            color: #000;
        }
        .btn-primary {
            background-color: #FF7043;
            border-color: #FF7043;
        }
        .btn-primary:hover {
            background-color: #FF5722;
            border-color: #FF5722;
        }
        #wait_message {
            color: #003366;
            font-size: 1.3rem;
            margin-top: 20px;
        }
        #wait_message span {
            vertical-align: middle;
        }
        .loader {
            width: 24px;
            height: 24px;
            border: 4px solid #003366;
            border-bottom-color: transparent;
            border-radius: 50%;
            display: inline-block;
            box-sizing: border-box;
            animation: rotation 1s linear infinite;
            margin-right: 10px;
        }
        @keyframes rotation {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
        #response_output {
            padding: 10px;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
            overflow-x: auto;
            word-wrap: break-word;
            white-space: pre-wrap;
            max-width: 100%;
            margin: 0;
            margin-top: 20px;
            color: #000;
        }
        .success-output {
            border: 2px solid #28a745;
            background-color: #d4edda;

        }
        .error-output {
            border: 2px solid #dc3545;
            background-color: #f8d7da;
        }
    </style>
    <script>
        function getQueryParam(name) {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(name);
        }

        function submitForm(event) {
            event.preventDefault();

            const outputElement = document.getElementById('response_output');
            const spinnerElement = document.getElementById('wait_message');

            spinnerElement.style.display = 'block';
            outputElement.style.display = 'none';

            const sshPubKey = document.getElementById('ssh_pub_key_textarea').value;
            const codeParam = getQueryParam('code');
            let postUrl = "/api/create-cert";

            if (codeParam) {
                postUrl += `?code=${codeParam}`;
            }

            fetch(postUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ssh_pub_key: sshPubKey
                }),
            })
            .then(response => {
                const contentType = response.headers.get("content-type");

                if (contentType && contentType.includes("application/json")) {
                    return response.json().then(data => ({ status: response.status, body: data }));
                }

                throw new Error(`Unexpected content type: ${contentType}`);
            })
            .then(responseData => {
                spinnerElement.style.display = 'none';

                if (responseData.status >= 200 && responseData.status < 300) {
                    outputElement.classList.add('success-output');
                    outputElement.classList.remove('error-output');
                } else {
                    outputElement.classList.add('error-output');
                    outputElement.classList.remove('success-output');
                }

                outputElement.innerText = JSON.stringify(responseData.body, null, 4);
                outputElement.style.display = 'block';
            })
            .catch((error) => {
                console.error('Error:', error);

                spinnerElement.style.display = 'none';
                outputElement.innerText = error.toString();
                outputElement.classList.add('error-output');
                outputElement.classList.remove('success-output');
                outputElement.style.display = 'block';
            });
        }
    </script>
</head>
<body>
    <div class="chatnpt_ad">
        <span class="emoji">&#127965;</span>
        <div class="message">
            <p>Let your winter blues defrost in <strong>Geese Islands'</strong> warmth.</p>
            <p class="tagline">&#x1F366; Here, the only thing frozen is your dessert! &#x1F366;</p>
        </div>
        <span class="emoji">&#129727;</span>
    </div>
    <div class="container">
        <h1>Request SSH Certificate</h1>
        <form onsubmit="submitForm(event)">
            <div class="form-group">
                <textarea class="form-control" id="ssh_pub_key_textarea" rows="8" placeholder="Paste your SSH public key here"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
        <div id="wait_message" style="display: none;">
            <span class="loader"></span><span>Please wait...</span>
        </div>
        <pre id="response_output" style="display:none;"></pre>
    </div>
</body>
</html>
    """

    return html_content


@app.route(route="create-cert", methods=['GET', 'POST'])
def create_cert(req: func.HttpRequest) -> func.HttpResponse:
    """Create SSH certificate."""
    logging.info('Python HTTP trigger function processed a request.')

    if req.method == "GET":
        return func.HttpResponse(
            get_form(),
            mimetype="text/html",
            status_code=200
        )

    try:
        ssh_pub_key, principal = parse_input(req.get_json())

        cert_fields = CertificateFields(
            serial=1,
            key_id=str(uuid.uuid4()),
            valid_after=datetime.utcnow() - timedelta(minutes=5),
            valid_before=datetime.utcnow() + timedelta(days=28),
            principals=[principal],
            critical_options=[],
            extensions=[
                "permit-X11-forwarding",
                "permit-agent-forwarding",
                "permit-port-forwarding",
                "permit-pty",
                "permit-user-rc"
            ]
        )

        ca_ssh_priv_key_b64 = secret_client.get_secret(CA_KEY_SECRET_NAME).value

        if ca_ssh_priv_key_b64 is not None:
            ca_ssh_priv_key_str = base64.b64decode(ca_ssh_priv_key_b64).decode('utf-8')
            ca_ssh_priv_key = PrivateKey.from_string(ca_ssh_priv_key_str)
        else:
            raise ValueError("Failed to retrieve Certificate Authority key.")

        ssh_cert = SSHCertificate.create(
            subject_pubkey=ssh_pub_key,
            ca_privkey=ca_ssh_priv_key,
            fields=cert_fields,
        )

        ssh_cert.sign()
        logging.info("SSH signed certificate: %s", ssh_cert.to_string())

        return func.HttpResponse(
            json.dumps({"ssh_cert": ssh_cert.to_string(), "principal": principal}),
            mimetype="application/json",
            status_code=200
        )
    except (ValueError, ValidationError) as err:
        return func.HttpResponse(
            json.dumps({"error": str(err)}),
            mimetype="application/json",
            status_code=400
        )
    except Exception as err:
        return func.HttpResponse(
            json.dumps({"error": f"Unexpected error: {str(err)}"}),
            mimetype="application/json",
            status_code=500
    )
