"""Read-only UI hierarchy coverage; all ADB processes are explicit local mocks."""
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET

import pytest
from cryptography.hazmat.primitives import serialization

from http_ctl import auth, client, operations, server as server_module


ADB = '/test-only/adb-never-executed'
TARGET = '/ui/hierarchy'
XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<hierarchy rotation="0"><node index="0" text="设置 &amp; Settings" '
    'resource-id="com.example:id/title" class="android.widget.TextView" '
    'package="com.example" content-desc="Open settings" bounds="[0,0][1080,120]" '
    'clickable="true" enabled="true"><node text="" /></node></hierarchy>'
).encode('utf-8')


@pytest.fixture(autouse=True)
def never_run_real_hierarchy_adb(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('hierarchy tests must never execute ADB or a remote shell')
    monkeypatch.setattr(operations, 'run_bounded', forbidden)


def mocked_adb(monkeypatch, result=(0, XML, b'', False, False)):
    calls = []

    def run(argv, timeout, **kwargs):
        calls.append((argv, timeout, kwargs))
        if len(calls) % 2 == 1:
            if isinstance(result, BaseException):
                raise result
            return result
        return 0, b'', b'', False, False

    monkeypatch.setattr(operations, 'run_bounded', run)
    return calls


def assert_bounded_commands(calls):
    assert len(calls) == 2  # Main operation plus independent finally cleanup.
    for argv, timeout, kwargs in calls:
        assert argv[:3] == [ADB, '-s', 'localhost:5555']
        assert 0 < timeout <= 60
        assert 0 < kwargs['output_limit'] <= operations.MAX_HIERARCHY + 1
    main, cleanup = calls[0][0], calls[1][0]
    assert calls[0][1] <= 30
    assert calls[1][1] <= 5
    for command in (main, cleanup):
        assert command[3:6] == ['exec-out', 'sh', '-c']
        assert len(command) == 7
        assert len(shlex.split(command[-1])) == 1  # Exactly one remotely quoted script.
    # Both calls contain exactly the same, generated server-owned directory.
    paths = set(re.findall(r'/data/local/tmp/http-ctl-ui-[0-9a-f]{32}', main[-1]))
    assert len(paths) == 1
    temporary = paths.pop()
    assert temporary in ' '.join(cleanup)
    assert 'trap ' in main[-1]
    assert 'umask 077' in main[-1]
    assert re.search(r'mkdir\s+-m\s+0?700\s+', main[-1])
    assert 'ulimit' in main[-1]
    assert 'timeout ' in main[-1]
    assert 'uiautomator dump' in main[-1]
    assert 'rmdir' in ' '.join(cleanup)
    return temporary


def test_hierarchy_accepts_exact_utf8_xml_and_preserves_node_attributes():
    assert operations.validate_hierarchy(XML) == XML
    root = ET.fromstring(operations.validate_hierarchy(XML))
    assert root.tag == 'hierarchy'
    node = root.find('node')
    assert node.attrib['text'] == '设置 & Settings'
    assert node.attrib['resource-id'] == 'com.example:id/title'
    assert node.attrib['bounds'] == '[0,0][1080,120]'


@pytest.mark.parametrize('xml', [
    b'', b'not XML', b'<hierarchy>', b'<hierarchy><node></hierarchy>',
    b'<not-hierarchy/>', b'<hierarchy/><hierarchy/>',
    b'UI hierchary dumped to: /tmp/example\n<hierarchy/>',
    b'<hierarchy/>trailing status output', b'<hierarchy>\xff</hierarchy>',
    b'<hierarchy><node text="\x00" /></hierarchy>',
    b'<!DOCTYPE hierarchy><hierarchy/>',
    b'<!DOCTYPE hierarchy [<!ENTITY secret "private">]><hierarchy><node text="&secret;"/></hierarchy>',
    b'<!DOCTYPE hierarchy SYSTEM "file:///test-only-do-not-read"><hierarchy/>',
    b'<!DOCTYPE hierarchy SYSTEM "https://example.invalid/never-fetch"><hierarchy/>',
    b'<!DOCTYPE hierarchy [<!ENTITY % x SYSTEM "file:///test-only-do-not-read">%x;]><hierarchy/>',
    '<?xml version="1.0" encoding="UTF-16"?><hierarchy/>'.encode('utf-16'),
])
def test_hierarchy_rejects_malformed_unsafe_or_wrapped_xml(xml):
    with pytest.raises(ValueError):
        operations.validate_hierarchy(xml)


def test_hierarchy_xml_size_boundary():
    assert operations.MAX_HIERARCHY == 1024 * 1024
    prefix, suffix = b'<hierarchy><node text="', b'"/></hierarchy>'
    exact = prefix + b'x' * (operations.MAX_HIERARCHY - len(prefix) - len(suffix)) + suffix
    assert len(exact) == operations.MAX_HIERARCHY
    assert operations.validate_hierarchy(exact) == exact
    with pytest.raises(ValueError):
        operations.validate_hierarchy(exact + b' ')


def test_hierarchy_main_and_cleanup_are_bounded_and_fixed_to_localhost(monkeypatch):
    calls = mocked_adb(monkeypatch)
    assert operations.ui_hierarchy(ADB) == XML
    assert_bounded_commands(calls)


def test_hierarchy_uses_unique_private_temporary_directories(monkeypatch):
    calls = mocked_adb(monkeypatch)
    assert operations.ui_hierarchy(ADB) == XML
    assert operations.ui_hierarchy(ADB) == XML
    first = assert_bounded_commands(calls[:2])
    second = assert_bounded_commands(calls[2:])
    assert first != second


@pytest.mark.parametrize('result', [
    (1, b'', b'PRIVATE-DUMP-ERROR', False, False),
    (-9, XML, b'', True, False),
    (0, XML, b'', False, True),
    (0, b'<hierarchy>', b'', False, False),
    (0, b'<!DOCTYPE hierarchy><hierarchy/>', b'', False, False),
    (0, b'x' * (1024 * 1024 + 1), b'', False, False),
    OSError('PRIVATE-ADB-ERROR'),
])
def test_hierarchy_cleanup_runs_after_main_failure(monkeypatch, result):
    calls = mocked_adb(monkeypatch, result)
    with pytest.raises((ValueError, OSError)):
        operations.ui_hierarchy(ADB)
    assert_bounded_commands(calls)


@pytest.fixture
def hierarchy_operation(monkeypatch):
    calls = []

    def hierarchy(adb):
        calls.append(adb)
        return XML

    monkeypatch.setattr(server_module, 'ui_hierarchy', hierarchy)
    return calls


def test_signed_hierarchy_returns_private_xml_without_shell_scope(service, hierarchy_operation, capsys):
    service.data['keys']['ui-only'] = service.key_record(service.private, ['ui:control'])
    service.write_config()
    response = service.request('GET', TARGET, key_id='ui-only')
    assert response.status == 200
    assert response.body == XML
    assert response.headers['Content-Type'] == 'application/xml; charset=utf-8'
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Connection'] == 'close'
    assert hierarchy_operation == ['/test-only/adb-not-executed']
    assert server_module.ROUTES[('GET', TARGET)] == ('ui:control', 0, 'application/octet-stream')
    logs = capsys.readouterr()
    assert 'com.example' not in logs.out + logs.err
    assert 'Settings' not in logs.out + logs.err


def test_hierarchy_requires_signature_before_any_adb(service, hierarchy_operation):
    response = service.request('GET', TARGET, headers={'Content-Type': 'application/octet-stream', 'Content-Length': '0'})
    assert response.status == 401
    assert hierarchy_operation == []


@pytest.mark.parametrize('scope', ['health:read', 'screenshot:read', 'shell:exec'])
def test_hierarchy_requires_existing_ui_control_scope(service, hierarchy_operation, scope):
    service.data['keys']['non-ui'] = service.key_record(service.private, [scope])
    service.write_config()
    response = service.request('GET', TARGET, key_id='non-ui')
    assert response.status == 403
    assert hierarchy_operation == []


def test_hierarchy_replay_is_rejected_before_second_operation(service, hierarchy_operation):
    headers = service.headers('GET', TARGET)
    assert service.request('GET', TARGET, headers=headers).status == 200
    assert service.request('GET', TARGET, headers=headers).status == 401
    service.restart()
    assert service.request('GET', TARGET, headers=headers).status == 401
    assert hierarchy_operation == ['/test-only/adb-not-executed']


def test_hierarchy_signature_cannot_be_reused_for_another_target(service, hierarchy_operation):
    headers = service.headers('GET', '/screenshot')
    assert service.request('GET', TARGET, headers=headers).status == 401
    assert hierarchy_operation == []


@pytest.mark.parametrize(('method', 'target', 'body', 'status'), [
    ('GET', TARGET + '?', b'', 400),
    ('GET', TARGET + '?serial=attacker:5555', b'', 400),
    ('GET', TARGET + '?path=/sdcard/private.xml', b'', 400),
    ('GET', TARGET + '?cmd=id', b'', 400),
    ('GET', TARGET + '?compressed=true', b'', 400),
    ('GET', TARGET, b'{"cmd":"id"}', 413),
    ('POST', TARGET, b'', 404),
    ('GET', TARGET + '/', b'', 404),
])
def test_hierarchy_rejects_request_controlled_options(service, hierarchy_operation, method, target, body, status):
    assert service.request(method, target, body).status == status
    assert hierarchy_operation == []


def test_hierarchy_obeys_operation_capacity(service, hierarchy_operation):
    assert service.server.operation_slots.acquire(blocking=False)
    assert service.server.operation_slots.acquire(blocking=False)
    try:
        assert service.request('GET', TARGET).status == 503
        assert hierarchy_operation == []
    finally:
        service.server.operation_slots.release()
        service.server.operation_slots.release()


@pytest.mark.parametrize('failure', [ValueError('PRIVATE-UI-XML'), OSError('PRIVATE-DEVICE-ERROR')])
def test_hierarchy_failure_is_generic_and_burns_nonce(service, monkeypatch, capsys, failure):
    calls = []

    def fail(adb):
        calls.append(adb)
        raise failure

    monkeypatch.setattr(server_module, 'ui_hierarchy', fail)
    headers = service.headers('GET', TARGET)
    response = service.request('GET', TARGET, headers=headers)
    assert response.status == 502
    assert response.json() == {'error': 'hierarchy failed'}
    assert service.request('GET', TARGET, headers=headers).status == 401
    assert len(calls) == 1
    logs = capsys.readouterr()
    assert 'PRIVATE-' not in logs.out + logs.err
    assert headers[auth.SIGNATURE_HEADER] not in logs.out + logs.err


def test_hierarchy_missing_adb_is_unavailable_without_execution(service, hierarchy_operation):
    service.server.adb = None
    assert service.request('GET', TARGET).status == 501
    assert hierarchy_operation == []


@pytest.fixture
def hierarchy_cli(service, monkeypatch):
    # Reuse the fixture's ephemeral in-memory test key; never generate, read, or
    # persist production credentials and never issue an external HTTP request.
    pem = service.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    monkeypatch.setenv('CTL_BASE_URL', 'https://ctl.example.test')
    monkeypatch.setenv('CTL_KEY_ID', 'test-key')
    monkeypatch.setattr(client, 'protected_read', lambda _: pem)
    calls = []

    def request(base, method, target, headers, body):
        calls.append((base, method, target, headers, body))
        response = service.request(method, target, body, headers=headers)
        assert response.status == 200
        return response.body

    monkeypatch.setattr(client, 'request', request)
    return calls


@pytest.mark.parametrize('custom', [False, True])
def test_cli_hierarchy_signs_empty_get_and_saves_private_xml(service, hierarchy_operation, hierarchy_cli, tmp_path, monkeypatch, capsys, custom):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ('custom hierarchy.xml' if custom else 'hierarchy.xml')
    args = ['hierarchy', str(target)] if custom else ['hierarchy']
    assert client.main(args) == 0
    assert target.read_bytes() == XML
    assert target.stat().st_mode & 0o777 == 0o600
    assert len(hierarchy_cli) == 1
    base, method, path, headers, body = hierarchy_cli[0]
    assert (base, method, path, body) == ('https://ctl.example.test', 'GET', TARGET, b'')
    assert headers['Content-Type'] == 'application/octet-stream'
    assert headers['Content-Digest'] == auth.digest(b'')
    assert service.request(method, path, headers=headers).status == 401
    assert 'Settings' not in capsys.readouterr().out


@pytest.mark.parametrize('response', [b'not XML', b'<hierarchy>', b'<!DOCTYPE hierarchy><hierarchy/>', b'x' * (1024 * 1024 + 1)], ids=['non-xml', 'malformed', 'dtd', 'oversize'])
def test_cli_hierarchy_rejects_invalid_response_without_overwriting(hierarchy_cli, tmp_path, monkeypatch, capsys, response):
    output = tmp_path / 'hierarchy.xml'
    output.write_bytes(b'preserve original')
    calls = []

    def invalid(*args):
        calls.append(args)
        return response

    monkeypatch.setattr(client, 'request', invalid)
    assert client.main(['hierarchy', str(output)]) == 1
    assert output.read_bytes() == b'preserve original'
    assert len(calls) == 1
    assert sorted(p.name for p in tmp_path.glob('.http-ctl-*')) == []
    logs = capsys.readouterr()
    assert logs.out == ''
    assert 'no automatic retry' in logs.err
    assert '<hierarchy' not in logs.err


def test_cli_hierarchy_replaces_symlink_not_its_target(service, hierarchy_operation, hierarchy_cli, tmp_path):
    outside = tmp_path / 'unrelated.xml'
    outside.write_bytes(b'preserve unrelated')
    output = tmp_path / 'hierarchy.xml'
    output.symlink_to(outside)
    assert client.main(['hierarchy', str(output)]) == 0
    assert not output.is_symlink()
    assert output.read_bytes() == XML
    assert outside.read_bytes() == b'preserve unrelated'
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('xml', [
    b'<hierarchy><unexpected/></hierarchy>',
    b'<hierarchy><hierarchy/></hierarchy>',
    b'<hierarchy>private text</hierarchy>',
    b'<hierarchy><node/>private tail</hierarchy>',
    b'<hierarchy><!--unsupported comment--></hierarchy>',
])
def test_hierarchy_rejects_non_uiautomator_structure(xml):
    with pytest.raises(ValueError):
        operations.validate_hierarchy(xml)


def test_hierarchy_node_count_is_bounded():
    accepted = b'<hierarchy>' + b'<node/>' * 9999 + b'</hierarchy>'
    assert operations.validate_hierarchy(accepted) == accepted
    rejected = b'<hierarchy>' + b'<node/>' * 10000 + b'</hierarchy>'
    with pytest.raises(ValueError):
        operations.validate_hierarchy(rejected)


def test_hierarchy_depth_is_bounded():
    accepted = b'<hierarchy>' + b'<node>' * 100 + b'</node>' * 100 + b'</hierarchy>'
    assert operations.validate_hierarchy(accepted) == accepted
    rejected = b'<hierarchy>' + b'<node>' * 101 + b'</node>' * 101 + b'</hierarchy>'
    with pytest.raises(ValueError):
        operations.validate_hierarchy(rejected)


@pytest.mark.parametrize('cleanup_result', [
    (1, b'', b'PRIVATE-CLEANUP-ERROR', False, False),
    (-9, b'', b'', True, False),
    (0, b'', b'', False, True),
    OSError('PRIVATE-CLEANUP-ERROR'),
])
def test_hierarchy_does_not_return_xml_when_cleanup_fails(monkeypatch, cleanup_result):
    calls = []

    def run(argv, timeout, **kwargs):
        calls.append((argv, timeout, kwargs))
        if len(calls) == 1:
            return 0, XML, b'', False, False
        if isinstance(cleanup_result, BaseException):
            raise cleanup_result
        return cleanup_result

    monkeypatch.setattr(operations, 'run_bounded', run)
    with pytest.raises((ValueError, OSError)):
        operations.ui_hierarchy(ADB)
    assert_bounded_commands(calls)


PASSWORD_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<hierarchy rotation="0">'
    '<node text="visible title" content-desc="visible description" password="false">'
    '<node password="true" text="SECRET-TEXT-ONE" content-desc="SECRET-DESC-ONE" '
    'resource-id="com.example:id/password" bounds="[0,0][100,100]" />'
    '<node text="visible child"><node password="true" text="SECRET-TEXT-TWO" '
    'content-desc="SECRET-DESC-TWO" /></node>'
    '</node></hierarchy>'
).encode('utf-8')


def assert_password_values_redacted(data):
    assert b'SECRET-' not in data
    root = ET.fromstring(data)
    nodes = list(root.iter('node'))
    password_nodes = [node for node in nodes if node.attrib.get('password') == 'true']
    assert len(password_nodes) == 2
    for node in password_nodes:
        assert not node.attrib.get('text')
        assert not node.attrib.get('content-desc')
    assert nodes[0].attrib['text'] == 'visible title'
    assert nodes[0].attrib['content-desc'] == 'visible description'
    assert password_nodes[0].attrib['resource-id'] == 'com.example:id/password'
    assert password_nodes[0].attrib['bounds'] == '[0,0][100,100]'


def test_hierarchy_redacts_password_fields_at_any_depth():
    assert_password_values_redacted(operations.validate_hierarchy(PASSWORD_XML))


def test_hierarchy_operation_never_returns_password_values(monkeypatch):
    calls = mocked_adb(monkeypatch, (0, PASSWORD_XML, b'', False, False))
    assert_password_values_redacted(operations.ui_hierarchy(ADB))
    assert_bounded_commands(calls)


def test_cli_hierarchy_saves_sanitized_return_value(hierarchy_cli, tmp_path, monkeypatch, capsys):
    output = tmp_path / 'hierarchy.xml'
    monkeypatch.setattr(client, 'request', lambda *args: PASSWORD_XML)
    assert client.main(['hierarchy', str(output)]) == 0
    assert_password_values_redacted(output.read_bytes())
    assert output.stat().st_mode & 0o777 == 0o600
    logs = capsys.readouterr()
    assert 'SECRET-' not in logs.out + logs.err


@pytest.mark.parametrize('encoding', ['ISO-8859-1', 'UTF-16', 'UTF-32', 'US-ASCII', 'windows-1252'])
def test_hierarchy_rejects_non_utf8_xml_declarations(encoding):
    for quote in ('"', "'"):
        declaration = f'<?xml version="1.0" encoding={quote}{encoding}{quote}?>'
        data = (declaration + '<hierarchy/>').encode('utf-8')
        with pytest.raises(ValueError):
            operations.validate_hierarchy(data)


@pytest.mark.parametrize('xml', [
    b'<?unexpected command?><hierarchy/>',
    b'<hierarchy/><?unexpected command?>',
    b'<hierarchy><?unexpected command?></hierarchy>',
    b'<?xml-stylesheet type="text/xsl" href="https://example.invalid/no-fetch"?><hierarchy/>',
    b'<?xml version="1.0"?><?xml-stylesheet href="file:///test-only-no-read"?><hierarchy/>',
    b'<hierarchy xmlns:x="urn:test"><node x:text="private"/></hierarchy>',
    b'<hierarchy><node xml:lang="en"/></hierarchy>',
])
def test_hierarchy_rejects_processing_instructions_and_namespaced_attributes(xml):
    with pytest.raises(ValueError):
        operations.validate_hierarchy(xml)


def test_signed_hierarchy_full_pipeline_redacts_and_ignores_other_configured_serial(service, monkeypatch):
    service.server.adb = ADB
    assert service.server.config.adb_serial != 'localhost:5555'
    calls = mocked_adb(monkeypatch, (0, PASSWORD_XML, b'', False, False))
    response = service.request('GET', TARGET)
    assert response.status == 200
    assert_password_values_redacted(response.body)
    assert_bounded_commands(calls)


def test_cli_hierarchy_empty_output_cannot_print_raw_xml(hierarchy_cli, monkeypatch, capsys):
    calls = []

    def response(*args):
        calls.append(args)
        return PASSWORD_XML

    monkeypatch.setattr(client, 'request', response)
    assert client.main(['hierarchy', '']) == 1
    assert calls == []
    logs = capsys.readouterr()
    assert logs.out == ''
    assert 'SECRET-' not in logs.err


def local_scripts(monkeypatch, tmp_path):
    """Materialize only the generated shell text in a private pytest directory.

    The real ADB path is never invoked. Every Android path is replaced before
    executing cleanup locally; the main script is run only for mkdir collision.
    """
    calls = mocked_adb(monkeypatch)
    operations.ui_hierarchy(ADB)
    directory = assert_bounded_commands(calls)
    scripts = [shlex.split(call[0][-1])[0] for call in calls]
    markers = [set(re.findall(r'\.owned-[0-9a-f]{32}', script)) for script in scripts]
    assert len(markers[0]) == 1
    assert markers[0] == markers[1]
    marker = markers[0].pop()
    local = tmp_path / 'generated-ui-directory'
    scripts = [script.replace(directory, str(local)) for script in scripts]
    assert all('/data/local/tmp/' not in script for script in scripts)
    assert scripts[0].index('mkdir -m 700') < scripts[0].index('trap cleanup EXIT')
    for script in scripts:
        assert 'rm -rf' not in script
    return local, marker, scripts


@pytest.mark.parametrize('kind', ['owned', 'missing_marker', 'wrong_marker', 'symlink_marker', 'symlink_directory', 'missing_directory', 'symlink_xml'])
def test_hierarchy_cleanup_only_removes_its_own_private_files(monkeypatch, tmp_path, kind):
    local, marker, (_, cleanup) = local_scripts(monkeypatch, tmp_path)
    outside = tmp_path / 'unrelated-directory'
    outside.mkdir(mode=0o700)
    protected = outside / 'hierarchy.xml'
    protected.write_bytes(b'unrelated protected data')
    (outside / marker).write_bytes(b'unrelated marker')
    if kind == 'symlink_directory':
        local.symlink_to(outside, target_is_directory=True)
    elif kind != 'missing_directory':
        local.mkdir(mode=0o700)
        xml = local / 'hierarchy.xml'
        if kind == 'symlink_xml':
            xml.symlink_to(protected)
        else:
            xml.write_bytes(b'private test hierarchy')
        if kind in ('owned', 'symlink_xml'):
            (local / marker).write_bytes(b'')
        elif kind == 'wrong_marker':
            (local / '.owned-wrong-instance').write_bytes(b'')
        elif kind == 'symlink_marker':
            (local / marker).symlink_to(outside / marker)
    result = subprocess.run(['/bin/sh', '-c', cleanup], capture_output=True, timeout=3, check=False)
    assert protected.read_bytes() == b'unrelated protected data'
    assert (outside / marker).read_bytes() == b'unrelated marker'
    if kind in ('owned', 'missing_directory', 'symlink_xml'):
        assert result.returncode == 0
        assert not local.exists()
    else:
        assert result.returncode != 0
        assert (local / 'hierarchy.xml').read_bytes() in (b'private test hierarchy', b'unrelated protected data')


def test_hierarchy_mkdir_collision_never_installs_destructive_cleanup(monkeypatch, tmp_path):
    local, marker, (main, cleanup) = local_scripts(monkeypatch, tmp_path)
    local.mkdir(mode=0o700)
    protected = local / 'hierarchy.xml'
    protected.write_bytes(b'preexisting data must survive')
    # Existing directory makes mkdir fail before any uiautomator/timeout call.
    result = subprocess.run(['/bin/sh', '-c', main], capture_output=True, timeout=3, check=False)
    assert result.returncode != 0
    assert not (local / marker).exists()
    assert protected.read_bytes() == b'preexisting data must survive'
    result = subprocess.run(['/bin/sh', '-c', cleanup], capture_output=True, timeout=3, check=False)
    assert result.returncode != 0
    assert protected.read_bytes() == b'preexisting data must survive'


def test_hierarchy_has_a_dedicated_single_dump_slot(service, hierarchy_operation):
    assert service.server.hierarchy_slot.acquire(blocking=False)
    try:
        response = service.request('GET', TARGET)
        assert response.status == 503
        assert response.json() == {'error': 'busy'}
        assert hierarchy_operation == []
        assert service.request('GET', '/health').status == 200
    finally:
        service.server.hierarchy_slot.release()
    assert service.request('GET', TARGET).status == 200
    assert hierarchy_operation == ['/test-only/adb-not-executed']


@pytest.mark.parametrize('failure', [ValueError('bad XML'), OSError('unavailable ADB')])
def test_hierarchy_releases_its_slot_after_failure(service, monkeypatch, failure):
    calls = []

    def hierarchy(adb):
        calls.append(adb)
        if len(calls) == 1:
            raise failure
        return XML

    monkeypatch.setattr(server_module, 'ui_hierarchy', hierarchy)
    assert service.request('GET', TARGET).status == 502
    assert service.request('GET', TARGET).status == 200
    assert len(calls) == 2
