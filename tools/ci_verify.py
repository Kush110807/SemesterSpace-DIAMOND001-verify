"""Verification transport/recording wrapper. Never changes the frozen recovery runner."""
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback
import zipfile

ROOT = pathlib.Path(os.environ.get('CI_ROOT', '/tmp/diamond-ci'))
PUB, PRIV = ROOT / 'public', ROOT / 'private'
PIN = '88d606ea940be945fa55124671c1a8deb57c7b04'
TREE = '1efa8ec205d125ac3fac9d934e99cfdccceff872'
HASHES = {
    'candidate.zip': '4b470a4229f8802055de9643864398a7339499f112b9cb7a9611b792f49df2f0',
    'recovery.zip': '2001cda5863b52660e2fd6a4222dc8f3d68ee2c13368085cff300eb21777fde3',
    '02_run_recovery.py': 'ae5ae7eac14ef320683dc8d7082a6cbc310b416993398f495fe3745bd8fac880',
    'AUTHENTIC_88d606e_WITH_BASE.bundle': '0a728be696094d4a395834aa3da143f2d8d4d6cec81ef53e7c91db22c1e8673d',
}


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')


def command(name, args, cwd=None, timeout=900):
    logs = PRIV / 'wrapper-logs'
    logs.mkdir(exist_ok=True)
    record = {'name': name, 'argv': list(map(str, args)), 'cwd': str(cwd or pathlib.Path.cwd()),
              'startUTC': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    with (logs / (name + '.stdout')).open('wb') as out, (logs / (name + '.stderr')).open('wb') as err:
        p = subprocess.Popen(record['argv'], cwd=cwd, stdout=out, stderr=err, start_new_session=True)
        record['pid'] = p.pid
        try:
            record['exitCode'] = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record['timedOut'] = True
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
            record['exitCode'] = p.returncode
    record['endUTC'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    write(logs / (name + '.json'), record)
    require(record['exitCode'] == 0, 'Command failed: ' + name + '; inspect encrypted raw evidence')
    return (logs / (name + '.stdout')).read_text(errors='replace').strip()


def qualify():
    require(os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch', 'Manual trigger required')
    require(os.environ['REPOSITORY_VISIBILITY'] == 'public', 'This exact design requires a public code/ciphertext-only repository')
    require(os.environ['PUBLICATION_APPROVED'] == 'true', 'Owner ciphertext/metadata publication approval required')
    require(os.environ['ZERO_COST_CHECKED'] == 'true', 'Owner billing/storage check required')
    require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'Fresh GitHub-hosted VM required')
    require(bool(os.environ.get('ImageOS')) and bool(os.environ.get('ImageVersion')), 'Hosted runner image identity unavailable')
    require(os.environ.get('RUNNER_ARCH') == 'X64' and platform.machine() == 'x86_64', 'x64 required')
    require(platform.system() == 'Linux', 'Linux required')
    os_release = pathlib.Path('/etc/os-release').read_text()
    require('VERSION_ID="24.04"' in os_release and 'ID=ubuntu' in os_release, 'Ubuntu 24.04 required')
    require(re.fullmatch('[0-9a-f]{40}', os.environ['APPROVED_COMMIT']) is not None, 'Invalid approved commit')
    require(re.fullmatch('[0-9a-f]{64}', os.environ['APPROVED_YAML_SHA256']) is not None, 'Invalid YAML hash')
    require(re.fullmatch('[0-9]+', os.environ['INPUT_ASSET_ID']) is not None, 'Invalid asset ID')
    require(re.fullmatch('[0-9a-f]{64}', os.environ['INPUT_CIPHER_SHA256']) is not None, 'Invalid ciphertext hash')
    require(bool(os.environ['APPROVAL_REFERENCE'].strip()), 'D approval reference required')
    head = command('ci-head', ['git', 'rev-parse', 'HEAD'])
    require(head == os.environ['GITHUB_SHA'] == os.environ['WORKFLOW_SHA'] == os.environ['APPROVED_COMMIT'], 'CI commit differs from approved commit')
    workflow = pathlib.Path('.github/workflows/t1-independent.yml')
    require(sha(workflow) == os.environ['APPROVED_YAML_SHA256'], 'Workflow YAML differs from D-approved bytes')
    require(command('ci-clean', ['git', 'status', '--porcelain=v1']) == '', 'CI configuration checkout is dirty')
    chromium = pathlib.Path('/usr/bin/chromium')
    require(chromium.is_file() and os.access(chromium, os.X_OK), 'Real /usr/bin/chromium unavailable; no substitute permitted')
    version = command('chromium-version', [str(chromium), '--version'])
    require(version.startswith('Chromium '), 'Executable did not identify as Chromium')
    metadata = {k: os.environ.get(k) for k in [
        'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_WORKFLOW', 'WORKFLOW_SHA', 'WORKFLOW_REF',
        'GITHUB_RUN_ID', 'GITHUB_RUN_NUMBER', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_ACTOR',
        'GITHUB_TRIGGERING_ACTOR', 'RUNNER_NAME', 'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_ENVIRONMENT',
        'ImageOS', 'ImageVersion', 'INPUT_ASSET_ID', 'INPUT_CIPHER_SHA256', 'APPROVAL_REFERENCE']}
    metadata.update({'attribution': 'GITHUB_HOSTED_CI_EXECUTED / D_EVIDENCE_REVIEWED',
                     'workflowSha256': sha(workflow), 'candidate': PIN, 'tree': TREE,
                     'wrapperSha256': sha(pathlib.Path(__file__)),
                     'chromiumVersion': version, 'chromiumResolvedPath': str(chromium.resolve()),
                     'chromiumLauncherSha256': sha(chromium), 'osRelease': os_release,
                     'cpuCount': os.cpu_count(), 'memoryInfo': pathlib.Path('/proc/meminfo').read_text(),
                     'diskFreeBytes': shutil.disk_usage(ROOT).free,
                     'inputIdentities': HASHES, 'SA001': 'OPEN P1',
                     'runURL': 'https://github.com/' + os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID']})
    write(PUB / 'CI_METADATA.json', metadata)
    shutil.copyfile(workflow, PUB / 'executed-workflow.yml')
    shutil.copyfile(__file__, PUB / 'executed-ci-wrapper.py')


def cipher_check():
    require(sha(PRIV / 'inputs.tar.gpg') == os.environ['INPUT_CIPHER_SHA256'], 'Ciphertext identity mismatch')
    asset = json.loads((PUB / 'input-asset.json').read_text())
    require(str(asset['id']) == os.environ['INPUT_ASSET_ID'] and asset['name'] == 'inputs.tar.gpg', 'Unexpected release asset')


def crypt(decrypt, src, dst):
    key = os.environ.get('CI_PASSPHRASE', '')
    require(re.fullmatch('[0-9a-f]{64}', key) is not None, 'CI_PASSPHRASE must be the local 256-bit random hex key')
    home = PRIV / 'gnupg'
    home.mkdir(mode=0o700, exist_ok=True)
    args = ['gpg', '--homedir', str(home), '--batch', '--yes', '--no-symkey-cache', '--pinentry-mode', 'loopback',
            '--passphrase-fd', '0', '--output', str(dst)]
    args += ['--decrypt', str(src)] if decrypt else ['--symmetric', '--cipher-algo', 'AES256', str(src)]
    with (PRIV / ('decrypt.stderr' if decrypt else 'seal.stderr')).open('wb') as log:
        p = subprocess.run(args, input=(key + '\n').encode(), stdout=subprocess.DEVNULL, stderr=log, timeout=600)
    require(p.returncode == 0, 'GPG operation failed; no plaintext upload allowed')


def unpack():
    cipher_check()
    crypt(True, PRIV / 'inputs.tar.gpg', PRIV / 'inputs.tar')
    with tarfile.open(PRIV / 'inputs.tar', 'r:') as t:
        members = t.getmembers()
        require(sorted(m.name for m in members) == ['candidate.zip', 'recovery.zip'], 'Unexpected transport members')
        for m in members:
            require(m.isfile() and 0 < m.size < 2**31, 'Invalid transport file')
            with t.extractfile(m) as src, (PRIV / m.name).open('wb') as dst:
                shutil.copyfileobj(src, dst)
    for name in ['candidate.zip', 'recovery.zip']:
        require(sha(PRIV / name) == HASHES[name], 'Original plaintext input hash mismatch: ' + name)
    recovery = PRIV / 'recovery'
    recovery.mkdir()
    with zipfile.ZipFile(PRIV / 'recovery.zip') as z:
        for info in z.infolist():
            p = pathlib.PurePosixPath(info.filename)
            require(not p.is_absolute() and '..' not in p.parts, 'Unsafe recovery ZIP path')
        z.extractall(recovery)
    for name in ['02_run_recovery.py', 'AUTHENTIC_88d606e_WITH_BASE.bundle']:
        require(sha(recovery / name) == HASHES[name], 'Frozen recovery member mismatch: ' + name)
    command('recovery-manifest', ['sha256sum', '-c', 'SHA256SUMS.txt'], cwd=recovery)
    write(PUB / 'INPUT_HASHES_VERIFIED.json', HASHES)


def execute():
    require(command('node-version', ['node', '--version']) == 'v24.19.0', 'Unexpected Node version')
    command('npm-version', ['npm', '--version'])
    command('python-version', [sys.executable, '--version'])
    command('git-version', ['git', '--version'])
    command('gpg-version', ['gpg', '--version'])
    require(not (PRIV / 'candidate').exists() and not (PRIV / 'output').exists(), 'Fresh checkout/output required')
    command('clone-bundle', ['git', 'clone', '--no-checkout', PRIV / 'recovery/AUTHENTIC_88d606e_WITH_BASE.bundle', PRIV / 'candidate'])
    command('detach-candidate', ['git', '-C', PRIV / 'candidate', 'checkout', '--detach', PIN])
    require(command('candidate-head', ['git', '-C', PRIV / 'candidate', 'rev-parse', 'HEAD']) == PIN, 'Candidate mismatch')
    require(command('candidate-tree', ['git', '-C', PRIV / 'candidate', 'rev-parse', 'HEAD^{tree}']) == TREE, 'Tree mismatch')
    runner = PRIV / 'recovery/02_run_recovery.py'
    require(sha(runner) == HASHES[runner.name], 'Runner changed')
    label = 'GITHUB_HOSTED_CI_EXECUTED; ' + os.environ['GITHUB_REPOSITORY'] + '; run ' + os.environ['GITHUB_RUN_ID'] + '; attempt ' + os.environ['GITHUB_RUN_ATTEMPT']
    command('unchanged-recovery', [sys.executable, runner, '--repo', PRIV / 'candidate', '--candidate-package', PRIV / 'candidate.zip',
                                 '--out', PRIV / 'output', '--executor-label', label], timeout=6600)
    result = json.loads((PRIV / 'output/RECOVERY_RESULT.json').read_text())
    require(result['status'] == 'EXECUTION_COMPLETED_FOR_D_REVIEW' and result['browserWorkflowsExecuted'] == 12, 'Recovery incomplete')
    require(len(result['runs']) == 36 and all(x['exitCode'] == 0 for x in result['runs']), 'Expected 36 successful recovery commands')
    require(sha(runner) == HASHES[runner.name], 'Runner changed during execution')
    text = (PRIV / 'output/logs/full-suite.stdout.log').read_text(errors='replace')
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    counts = {}
    for key, expected in [('tests', 540), ('pass', 540), ('fail', 0), ('cancelled', 0), ('skipped', 0), ('todo', 0)]:
        values = re.findall(r'^\s*(?:#|ℹ)?\s*' + key + r'\s+(\d+)\s*$', text, re.MULTILINE)
        require(bool(values) and int(values[-1]) == expected, 'Full-suite summary mismatch: ' + key)
        counts[key] = int(values[-1])
    metadata = json.loads((PUB / 'CI_METADATA.json').read_text())
    require(command('ci-final-head', ['git', 'rev-parse', 'HEAD']) == os.environ['APPROVED_COMMIT'], 'CI config HEAD changed')
    require(command('ci-final-clean', ['git', 'status', '--porcelain=v1']) == '', 'CI config changed')
    require(sha(pathlib.Path(__file__)) == metadata['wrapperSha256'] and sha(pathlib.Path('.github/workflows/t1-independent.yml')) == metadata['workflowSha256'], 'CI verification code changed')
    write(PUB / 'EXECUTION_STATUS.json', {'status': result['status'], 'commands': 36, 'browserWorkflows': 12,
                                       'fullSuiteCounts': counts,
                                       'acceptance': 'PENDING_D_ASSERTION_REVIEW'})


def seal():
    PUB.mkdir(parents=True, exist_ok=True)
    PRIV.mkdir(parents=True, exist_ok=True)
    write(PUB / 'COLLECTION_STATUS.json', {'gateStepOutcome': os.environ.get('GATE_OUTCOME'),
                                         'status': 'SEALING', 'notAutomaticAcceptance': True})
    evidence = PRIV / 'ci-evidence.zip'
    with zipfile.ZipFile(evidence, 'w', zipfile.ZIP_DEFLATED) as z:
        files = []
        for folder in [PRIV / 'wrapper-logs', PRIV / 'output', PUB]:
            if not folder.exists():
                continue
            for p in sorted(folder.rglob('*')):
                rel = p.relative_to(folder)
                if not p.is_file() or any(x in rel.parts for x in ['input-artifacts', 'input-evidence', 'npm-cache', 'profiles', 'node_modules']):
                    continue
                if folder == PUB and p.name in ['evidence.zip.gpg', 'PUBLIC_SHA256SUMS.txt']:
                    continue
                arc = folder.name + '/' + rel.as_posix()
                z.write(p, arc)
                files.append((sha(p), arc))
        for p in sorted(PRIV.glob('wrapper-error-*.txt')) + sorted(PRIV.glob('*.stderr')):
            arc = 'transport-logs/' + p.name
            z.write(p, arc)
            files.append((sha(p), arc))
        z.writestr('CI_EVIDENCE_SHA256SUMS.txt', ''.join(h + '  ' + n + '\n' for h, n in files))
    crypt(False, evidence, PUB / 'evidence.zip.gpg')
    write(PUB / 'COLLECTION_STATUS.json', {'gateStepOutcome': os.environ.get('GATE_OUTCOME'), 'status': 'ENCRYPTED_EVIDENCE_COLLECTED',
                                         'plaintextEvidenceSha256': sha(evidence), 'ciphertextEvidenceSha256': sha(PUB / 'evidence.zip.gpg'),
                                         'acceptance': 'PENDING_D_ASSERTION_REVIEW'})
    (PUB / 'PUBLIC_SHA256SUMS.txt').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(PUB.iterdir())
                                                   if p.is_file() and p.name != 'PUBLIC_SHA256SUMS.txt'))


if __name__ == '__main__':
    require(len(sys.argv) == 2 and sys.argv[1] in ['qualify', 'cipher-check', 'unpack', 'execute', 'seal'], 'Invalid wrapper command')
    try:
        {'qualify': qualify, 'cipher-check': cipher_check, 'unpack': unpack, 'execute': execute, 'seal': seal}[sys.argv[1]]()
    except Exception as e:
        PRIV.mkdir(parents=True, exist_ok=True)
        (PRIV / ('wrapper-error-' + sys.argv[1] + '.txt')).write_text(traceback.format_exc())
        # Avoid reflecting data from encrypted sources into public GitHub logs.
        print('CI verification stage failed: ' + sys.argv[1] + '; inspect encrypted evidence and step outcome.', file=sys.stderr)
        sys.exit(1)
