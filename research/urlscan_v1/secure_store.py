"""Authenticated encrypted archives; RSA private keys never belong on CI runners.

Envelope v1: RSA-3072+ OAEP-SHA256 wraps a fresh AES-256-GCM key.
The JSON header is authenticated as AAD. The ZIP is decrypted and authenticated
before any extraction. This is an application envelope, not a standard HAR format.
"""
import argparse
import base64
import io
import json
import os
from pathlib import Path, PurePosixPath
import struct
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .collector import encoded, sha

MAGIC = b'URLSCAN-ENVELOPE-1\n'
MAX_ARCHIVE = 512_000_000
MAX_FILES = 10000
LABEL = b'urlscan-evidence-envelope-v1'


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(data):
    return base64.b64decode(data, validate=True)


def fingerprint(key):
    return sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def public_key(data):
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError('RSA >=3072 required')
    return key


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=LABEL)


def keygen(private_path, public_path):
    if private_path.exists() or public_path.exists():
        raise ValueError('key already exists')
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    write_new(private_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_new(public_path, key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return fingerprint(key.public_key())


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def pack(folder):
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('invalid archive directory')
    stream, total, count = io.BytesIO(), 0, 0
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob('*')):
            if path.is_symlink():
                raise ValueError('symlink in archive')
            if not path.is_file():
                continue
            total += path.stat().st_size; count += 1
            if total > MAX_ARCHIVE or count > MAX_FILES:
                raise ValueError('archive limit exceeded')
            archive.write(path, path.relative_to(folder).as_posix())
    return stream.getvalue()


def seal(data, recipient):
    if len(data) > MAX_ARCHIVE:
        raise ValueError('archive limit exceeded')
    key = public_key(recipient)
    aes_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    header = encoded({'version': 1, 'algorithm': 'RSA-OAEP-SHA256+AES-256-GCM',
        'recipient_sha256': fingerprint(key), 'wrapped_key': b64(key.encrypt(aes_key, oaep())), 'nonce': b64(nonce)})
    return MAGIC + struct.pack('>I', len(header)) + header + AESGCM(aes_key).encrypt(nonce, data, header)


def unseal(blob, private_pem):
    if not blob.startswith(MAGIC) or len(blob) > MAX_ARCHIVE + 16384:
        raise ValueError('invalid envelope')
    offset = len(MAGIC)
    size = struct.unpack('>I', blob[offset:offset+4])[0]
    if not 1 <= size <= 8192:
        raise ValueError('invalid envelope header')
    header = blob[offset+4:offset+4+size]
    obj = json.loads(header)
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise ValueError('invalid private key')
    if obj.get('version') != 1 or obj.get('algorithm') != 'RSA-OAEP-SHA256+AES-256-GCM' or obj.get('recipient_sha256') != fingerprint(key.public_key()):
        raise ValueError('envelope identity mismatch')
    aes_key = key.decrypt(unb64(obj['wrapped_key']), oaep())
    return AESGCM(aes_key).decrypt(unb64(obj['nonce']), blob[offset+4+size:], header)


def unpack(data, output):
    # Preflight the entire archive; never zip.extractall untrusted path names.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_ARCHIVE:
            raise ValueError('archive limit exceeded')
        seen = set()
        for info in infos:
            p = PurePosixPath(info.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in info.filename or ':' in info.filename or not p.parts or info.filename in seen:
                raise ValueError('unsafe archive path')
            if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('non-file archive member')
            seen.add(info.filename)
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
        for info in infos:
            path = output / info.filename
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(path, archive.read(info))


def seal_directory(folder, destination, recipient):
    blob = seal(pack(folder), recipient.read_bytes())
    write_new(destination, blob)
    return {'encrypted_archive_sha256': sha(blob), 'encrypted_bytes': len(blob),
            'recipient_sha256': fingerprint(public_key(recipient.read_bytes()))}


def input_encrypt(data, key):
    if len(key) != 32:
        raise ValueError('invalid input key')
    nonce = os.urandom(12)
    return b'USINPUT1' + nonce + AESGCM(key).encrypt(nonce, data, b'urlscan-private-candidates-v1')


def input_decrypt(blob, key):
    if not blob.startswith(b'USINPUT1') or len(blob) > 2_000_000 or len(key) != 32:
        raise ValueError('invalid candidate envelope')
    return AESGCM(key).decrypt(blob[8:20], blob[20:], b'urlscan-private-candidates-v1')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    key = commands.add_parser('keygen')
    key.add_argument('--private-key', type=Path, required=True)
    key.add_argument('--public-key', type=Path, required=True)
    encrypt = commands.add_parser('encrypt')
    encrypt.add_argument('--directory', type=Path, required=True)
    encrypt.add_argument('--output', type=Path, required=True)
    encrypt.add_argument('--public-key', type=Path, required=True)
    decrypt = commands.add_parser('decrypt')
    decrypt.add_argument('--input', type=Path, required=True)
    decrypt.add_argument('--output', type=Path, required=True)
    decrypt.add_argument('--private-key', type=Path, required=True)
    args = p.parse_args()
    if args.command == 'keygen':
        print(keygen(args.private_key, args.public_key))
    elif args.command == 'encrypt':
        print(encoded(seal_directory(args.directory, args.output, args.public_key)).decode())
    else:
        unpack(unseal(args.input.read_bytes(), args.private_key.read_bytes()), args.output)
        print('authenticated_archive_restored')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('encrypted_storage_operation_failed') from None
