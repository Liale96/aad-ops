import base64
import uuid
import requests
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

# Dependencies: pip install cryptography pyjwt requests

def load_certificate(pfx_path: str, password: str):
    """Load private key and certificate from a PFX file."""
    with open(pfx_path, 'rb') as f:
        private_key, cert, _ = load_key_and_certificates(f.read(), password.encode() if password else None)
    return private_key, cert


def get_thumbprint(cert) -> str:
    fingerprint = cert.fingerprint(hashes.SHA1())
    return base64.urlsafe_b64encode(fingerprint).decode().rstrip('=')


def generate_jwt(payload: dict, private_key, thumbprint: str) -> str:
    headers = {"alg": "RS256", "x5t": thumbprint}
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def generate_client_assertion(client_id: str, tenant_id: str, private_key, cert) -> str:
    now = datetime.utcnow()
    payload = {
        "aud": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "exp": now + timedelta(minutes=10)
    }
    return generate_jwt(payload, private_key, get_thumbprint(cert))


def get_access_token(client_assertion: str, client_id: str, tenant_id: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default"
    }
    r = requests.post(url, data=data)
    r.raise_for_status()
    return r.json()["access_token"]


def generate_pop_token(object_id: str, private_key, cert) -> str:
    now = datetime.utcnow()
    payload = {
        "aud": "00000002-0000-0000-c000-000000000000",
        "iss": object_id,
        "nbf": now,
        "exp": now + timedelta(minutes=10)
    }
    return generate_jwt(payload, private_key, get_thumbprint(cert))


def add_key(app_id: str, pop_token: str, access_token: str, new_cert_path: str):
    url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addKey"
    from cryptography.x509 import load_pem_x509_certificate
    with open(new_cert_path, 'rb') as f:
        cert_data = f.read()
    cert = load_pem_x509_certificate(cert_data)
    key_b64 = base64.b64encode(cert.public_bytes(Encoding.DER)).decode()
    body = {
        "keyCredential": {"type": "AsymmetricX509Cert", "usage": "Verify", "key": key_b64},
        "proof": pop_token
    }
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    r = requests.post(url, json=body, headers=headers)
    r.raise_for_status()
    return r.json()


def remove_key(app_id: str, key_id: str, pop_token: str, access_token: str) -> None:
    url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/removeKey"
    body = {"keyId": key_id, "proof": pop_token}
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    r = requests.post(url, json=body, headers=headers)
    r.raise_for_status()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Roll Azure AD application certificate via PoP token")
    parser.add_argument('--pfx', required=True)
    parser.add_argument('--pfx-password', default='')
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--tenant-id', required=True)
    parser.add_argument('--app-object-id', required=True)
    parser.add_argument('--new-cert', help='Path to PEM public cert to add')
    parser.add_argument('--remove-key-id', help='Key ID (UUID) to remove')
    args = parser.parse_args()

    private_key, cert = load_certificate(args.pfx, args.pfx_password)
    client_assertion = generate_client_assertion(args.client_id, args.tenant_id, private_key, cert)
    access_token = get_access_token(client_assertion, args.client_id, args.tenant_id)
    pop = generate_pop_token(args.app_object_id, private_key, cert)

    if args.new_cert:
        print("Adding new certificate...")
        resp = add_key(args.app_object_id, pop, access_token, args.new_cert)
        print("Added key:", resp)
    if args.remove_key_id:
        print(f"Removing key {args.remove_key_id}...")
        remove_key(args.app_object_id, args.remove_key_id, pop, access_token)
        print("Removed key successfully.")
