#!/usr/bin/env python3
"""Deployment-owned, externally authenticated UTC boundary for PGK v21.

The host wall clock is deliberately not consulted.  Each observation is the
generation time of an RFC 3161 token over a caller supplied, fresh nonce and
challenge.  The token signature, message imprint, nonce, certificate chain,
EKU, validity interval and pinned deployment trust root are verified locally.
Network/TSA failure is a hard failure: the promotion kernel then returns DENY.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from pyasn1.codec.der import decoder, encoder
from rfc3161ng import (RemoteTimestamper, TimeStampToken, check_timestamp,
                       get_timestamp)

# This authenticated HTTPS endpoint fronts DigiCert's RFC 3161 service.  The
# response remains independently verified below; TLS is defense in depth and
# prevents the plaintext acquisition defect from V15.
TSA_URL = "https://rfc3161.ai.moda"
TSA_ROOT_FILE = "digicert-assured-id-root-ca.der"
TSA_ROOT_SHA256 = "3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c"
MAX_CHAIN_CERTIFICATES = 6
TSA_NETWORK_TIMEOUT_SECONDS = 10


def _verify_certificate_signature(child, issuer):
    key = issuer.public_key()
    signature = child.signature
    payload = child.tbs_certificate_bytes
    algorithm = child.signature_hash_algorithm
    parameters = child.signature_algorithm_parameters
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, payload, parameters or padding.PKCS1v15(), algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, payload, parameters or ec.ECDSA(algorithm))
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key.verify(signature, payload)
    else:
        raise ValueError("unsupported TSA certificate key")


def _validate_ca_certificate(certificate):
    basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not basic.ca:
        raise ValueError("timestamp issuer is not CA")
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.key_cert_sign:
        raise ValueError("timestamp issuer key usage")


def _embedded_certificates(token):
    parsed, residue = decoder.decode(token, asn1Spec=TimeStampToken())
    if residue:
        raise ValueError("trailing timestamp token data")
    encoded = []
    for choice in parsed["content"]["certificates"]:
        encoded.append(encoder.encode(choice["certificate"]))
    if not 1 <= len(encoded) <= MAX_CHAIN_CERTIFICATES:
        raise ValueError("timestamp certificate chain")
    return parsed, encoded, [x509.load_der_x509_certificate(raw) for raw in encoded]


def _validate_chain(token, digest, nonce, generated_at):
    expected_root_path = Path(__file__).resolve().with_name(TSA_ROOT_FILE)
    root_raw = expected_root_path.read_bytes()
    if hashlib.sha256(root_raw).hexdigest() != TSA_ROOT_SHA256:
        raise ValueError("timestamp trust root drift")
    pinned_root = x509.load_der_x509_certificate(root_raw)
    # A deployment trust anchor is not merely the last certificate that the
    # TSA happened to return.  It must be an independently provisioned,
    # self-signed CA whose self-signature is valid.  The currently served
    # DigiCert Trusted Root G4 is a cross certificate and is therefore checked
    # as an ordinary intermediate on the path to this root.
    _validate_ca_certificate(pinned_root)
    if pinned_root.subject != pinned_root.issuer:
        raise ValueError("timestamp trust anchor")
    _verify_certificate_signature(pinned_root, pinned_root)
    parsed, cert_raw, certificates = _embedded_certificates(token)

    signer_info = parsed["content"]["signerInfos"][0]
    signer_serial = int(signer_info["issuerAndSerialNumber"]["serialNumber"])
    matches = [i for i, cert in enumerate(certificates)
               if cert.serial_number == signer_serial]
    if len(matches) != 1:
        raise ValueError("timestamp signer certificate")
    leaf_index = matches[0]
    leaf = certificates[leaf_index]
    if not check_timestamp(token, certificate=cert_raw[leaf_index], digest=digest,
                           hashname="sha256", nonce=nonce):
        raise ValueError("timestamp signature")
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if list(eku) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError("timestamp EKU")

    by_subject = {}
    for cert in certificates:
        key = cert.subject.rfc4514_string()
        if key in by_subject:
            raise ValueError("timestamp duplicate chain subject")
        by_subject[key] = cert
    current = leaf
    visited = set()
    while current.fingerprint(hashes.SHA256()) != pinned_root.fingerprint(hashes.SHA256()):
        fingerprint = current.fingerprint(hashes.SHA256())
        if fingerprint in visited:
            raise ValueError("timestamp chain loop")
        visited.add(fingerprint)
        issuer = by_subject.get(current.issuer.rfc4514_string())
        if issuer is None:
            if current.issuer != pinned_root.subject:
                raise ValueError("timestamp chain incomplete")
            issuer = pinned_root
        _validate_ca_certificate(issuer)
        if generated_at < current.not_valid_before_utc or generated_at > current.not_valid_after_utc:
            raise ValueError("timestamp certificate validity")
        _verify_certificate_signature(current, issuer)
        current = issuer
    if generated_at < pinned_root.not_valid_before_utc or generated_at > pinned_root.not_valid_after_utc:
        raise ValueError("timestamp root validity")
    return {
        "tsa_url": TSA_URL,
        "token_sha256": hashlib.sha256(token).hexdigest(),
        "trust_root_sha256": TSA_ROOT_SHA256,
        "leaf_sha256": hashlib.sha256(cert_raw[leaf_index]).hexdigest(),
        "chain_certificates": len(certificates),
    }


def authoritative_utc_now(challenge, *, token_bytes=None):
    """Return authenticated UTC plus token metadata for a fresh challenge."""
    if type(challenge) is not bytes or len(challenge) != 32:
        raise ValueError("clock challenge")
    request_nonce_raw = os.urandom(16)
    request_nonce = int.from_bytes(request_nonce_raw, "big")
    digest = hashlib.sha256(b"PGK-v21-RFC3161\x00" + challenge + request_nonce_raw).digest()
    token = token_bytes
    if token is None:
        token = RemoteTimestamper(
            TSA_URL, hashname="sha256", include_tsa_certificate=True,
            timeout=TSA_NETWORK_TIMEOUT_SECONDS,
        )(digest=digest, include_tsa_certificate=True, nonce=request_nonce)
    elif type(token) is not bytes:
        raise ValueError("timestamp token type")
    generated_at = get_timestamp(token, naive=False).astimezone(dt.timezone.utc)
    verification = _validate_chain(token, digest, request_nonce, generated_at)
    verification.update({
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "request_nonce_sha256": hashlib.sha256(request_nonce_raw).hexdigest(),
        "observed_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    return generated_at, verification
