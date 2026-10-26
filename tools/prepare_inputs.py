"""Owner-local packaging only; creates ciphertext, never uploads or runs the candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile

EXPECTED = {
    'candidate.zip': '4b470a4229f8802055de9643864398a7339499f112b9cb7a9611b792f49df2f0',
    'recovery.zip': '2001cda5863b52660e2fd6a4222dc8f3d68ee2c13368085cff300eb21777fde3',
}


def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--candidate', required=True, type=Path)
    p.add_argument('--recovery', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    inputs = {'candidate.zip': a.candidate.resolve(), 'recovery.zip': a.recovery.resolve()}
    for name, path in inputs.items():
        if digest(path) != EXPECTED[name]:
            raise SystemExit('Original input identity mismatch: ' + name)
    probe = subprocess.run(['git', '-C', str(a.out.resolve().parent), 'rev-parse', '--show-toplevel'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode == 0:
        raise SystemExit('Output must be outside every Git repository; it contains a secret key.')
    os.umask(0o077)
    a.out.mkdir(mode=0o700)  # Must be new and OUTSIDE any Git repository.
    key = secrets.token_hex(32)
    (a.out / 'CI_PASSPHRASE.key').write_text(key + '\n')
    plain = a.out / 'inputs.tar'
    with tarfile.open(plain, 'w') as t:
        for name, path in inputs.items():
            t.add(path, arcname=name, recursive=False)
    home = a.out / 'gnupg'
    home.mkdir(mode=0o700)
    cipher = a.out / 'inputs.tar.gpg'
    subprocess.run(['gpg', '--homedir', str(home), '--batch', '--yes', '--no-symkey-cache',
                    '--pinentry-mode', 'loopback', '--passphrase-fd', '0', '--symmetric',
                    '--cipher-algo', 'AES256', '--output', str(cipher), str(plain)],
                   input=(key + '\n').encode(), check=True)
    plain.unlink()
    result = {'plaintextInputHashes': EXPECTED, 'ciphertextName': cipher.name,
              'ciphertextSha256': digest(cipher), 'ciphertextBytes': cipher.stat().st_size,
              'keyPolicy': 'Secret file stays local; enter its value only in GitHub CI_PASSPHRASE secret. Never upload key.'}
    (a.out / 'INPUT_BUILDINFO.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
