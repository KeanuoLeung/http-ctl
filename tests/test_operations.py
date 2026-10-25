"""File confinement and local subprocess bounds, with no ADB or phone access."""
import os
import sys
import time

import pytest

from http_ctl import operations


@pytest.fixture
def file_root(tmp_path):
    root = tmp_path / 'files'
    root.mkdir(mode=0o700)
    return root


@pytest.mark.parametrize('path', ['', '.', '..', '../secret', 'a/../secret', '/absolute', 'a//b', 'a/./b', 'a/', 'a\\b', 'a\x00b', 'a\nb', 'a\x7fb', 'a' * 4097])
def test_file_paths_reject_traversal_and_controls(file_root, path):
    with pytest.raises((ValueError, OSError)):
        operations.download(str(file_root), path)
    with pytest.raises((ValueError, OSError)):
        operations.upload(str(file_root), path, b'data')


def test_upload_download_roundtrip_and_private_atomic_replacement(file_root):
    target = file_root / 'notes.bin'
    target.write_bytes(b'old')
    old_inode = target.stat().st_ino
    operations.upload(str(file_root), 'notes.bin', b'new\x00bytes')
    assert target.stat().st_ino != old_inode
    assert target.stat().st_mode & 0o777 == 0o600
    assert operations.download(str(file_root), 'notes.bin') == b'new\x00bytes'
    assert sorted(p.name for p in file_root.iterdir()) == ['notes.bin']


def test_nested_file_access(file_root):
    (file_root / 'nested').mkdir()
    operations.upload(str(file_root), 'nested/name', b'contents')
    assert operations.download(str(file_root), 'nested/name') == b'contents'


@pytest.mark.parametrize('kind', ['leaf_symlink', 'directory_symlink', 'root_symlink', 'ancestor_symlink', 'hardlink', 'fifo'])
def test_symlinks_hardlinks_and_special_files_rejected(file_root, tmp_path, kind):
    outside = tmp_path / 'outside'
    outside.mkdir()
    secret = outside / 'secret'
    secret.write_bytes(b'outside-secret')
    root, relative = str(file_root), 'target'
    if kind == 'leaf_symlink':
        (file_root / 'target').symlink_to(secret)
    elif kind == 'directory_symlink':
        (file_root / 'alias').symlink_to(outside, target_is_directory=True)
        relative = 'alias/secret'
    elif kind == 'root_symlink':
        alias = tmp_path / 'alias'
        alias.symlink_to(file_root, target_is_directory=True)
        root, relative = str(alias), 'target'
    elif kind == 'ancestor_symlink':
        alias = tmp_path / 'alias'
        alias.symlink_to(tmp_path, target_is_directory=True)
        root = str(alias / 'files')
    elif kind == 'hardlink':
        os.link(secret, file_root / 'target')
    else:
        os.mkfifo(file_root / 'target', 0o600)
    for function, args in [(operations.download, (root, relative)), (operations.upload, (root, relative, b'overwrite'))]:
        with pytest.raises((ValueError, OSError)):
            function(*args)
    assert secret.read_bytes() == b'outside-secret'


def test_root_writable_by_other_users_is_rejected(file_root):
    file_root.chmod(0o777)
    with pytest.raises(ValueError):
        operations.upload(str(file_root), 'target', b'payload')


def test_upload_leaf_swap_never_follows_raced_symlink(file_root, tmp_path, monkeypatch):
    target = file_root / 'target'
    target.write_bytes(b'old')
    outside = tmp_path / 'outside-secret'
    outside.write_bytes(b'must-not-change')
    real_replace = os.replace
    raced = []
    def swap_leaf_then_replace(source, destination, **kwargs):
        assert destination == 'target'
        target.unlink()
        target.symlink_to(outside)
        raced.append(True)
        return real_replace(source, destination, **kwargs)
    monkeypatch.setattr(operations.os, 'replace', swap_leaf_then_replace)
    operations.upload(str(file_root), 'target', b'new')
    assert raced == [True]
    assert not target.is_symlink()
    assert target.read_bytes() == b'new'
    assert outside.read_bytes() == b'must-not-change'


@pytest.mark.parametrize('operation', ['download', 'upload'])
def test_open_parent_descriptor_survives_directory_swap(file_root, tmp_path, monkeypatch, operation):
    nested = file_root / 'nested'
    nested.mkdir()
    (nested / 'target').write_bytes(b'authorized')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'target').write_bytes(b'outside-secret')
    real_parent = operations.parent_fd
    def raced_parent(root, relative):
        descriptor, name = real_parent(root, relative)
        nested.rename(file_root / 'moved')
        nested.symlink_to(outside, target_is_directory=True)
        return descriptor, name
    monkeypatch.setattr(operations, 'parent_fd', raced_parent)
    if operation == 'download':
        assert operations.download(str(file_root), 'nested/target') == b'authorized'
    else:
        operations.upload(str(file_root), 'nested/target', b'updated')
        assert (file_root / 'moved' / 'target').read_bytes() == b'updated'
    assert (outside / 'target').read_bytes() == b'outside-secret'


def test_download_leaf_swap_to_symlink_rejected(file_root, tmp_path, monkeypatch):
    target = file_root / 'target'
    target.write_bytes(b'authorized')
    outside = tmp_path / 'secret'
    outside.write_bytes(b'outside-secret')
    real_parent = operations.parent_fd
    def raced_parent(root, relative):
        descriptor, name = real_parent(root, relative)
        target.unlink()
        target.symlink_to(outside)
        return descriptor, name
    monkeypatch.setattr(operations, 'parent_fd', raced_parent)
    with pytest.raises(OSError):
        operations.download(str(file_root), 'target')


def test_failed_upload_preserves_original_and_cleans_temporary(file_root, monkeypatch):
    target = file_root / 'target'
    target.write_bytes(b'old')
    def fail_replace(*args, **kwargs):
        raise OSError('simulated atomic replacement failure')
    monkeypatch.setattr(operations.os, 'replace', fail_replace)
    with pytest.raises(OSError):
        operations.upload(str(file_root), 'target', b'new')
    assert target.read_bytes() == b'old'
    assert [p.name for p in file_root.iterdir()] == ['target']


def test_download_size_bound(file_root, monkeypatch):
    monkeypatch.setattr(operations, 'MAX_FILE', 8)
    (file_root / 'target').write_bytes(b'123456789')
    with pytest.raises(OverflowError):
        operations.download(str(file_root), 'target')


def test_bounded_local_subprocess_output():
    # Only this Python interpreter is run, never ADB, a shell, or user commands.
    result = operations.run_bounded([sys.executable, '-c', 'import sys;sys.stdout.write("x"*200000);sys.stdout.flush()'], 3, output_limit=1000)
    code, out, err, timed, truncated = result
    assert len(out) == 1000
    assert len(err) <= 1000
    assert truncated is True
    assert timed is False


def test_bounded_local_subprocess_stderr():
    result = operations.run_bounded([sys.executable, '-c', 'import sys;sys.stderr.write("x"*200000);sys.stderr.flush()'], 3, output_limit=1000)
    assert len(result[2]) == 1000
    assert result[4] is True


def test_bounded_local_subprocess_timeout():
    started = time.monotonic()
    result = operations.run_bounded([sys.executable, '-c', 'import time;time.sleep(30)'], 0.15)
    assert result[3] is True
    assert result[0] != 0
    assert time.monotonic() - started < 3


def test_bounded_local_subprocess_normal_exit():
    result = operations.run_bounded([sys.executable, '-c', 'import sys;print("ok");print("err",file=sys.stderr)'], 3)
    assert result == (0, b'ok\n', b'err\n', False, False)


@pytest.mark.parametrize('ui_request', [
    {'action': 'tap', 'x': True, 'y': 0}, {'action': 'tap', 'x': -1, 'y': 0},
    {'action': 'tap', 'x': 0, 'y': 10001}, {'action': 'tap', 'x': 0, 'y': 0, 'cmd': 'id'},
    {'action': 'text', 'text': 'hello;id'}, {'action': 'text', 'text': '$(id)'},
    {'action': 'text', 'text': '`id`'}, {'action': 'text', 'text': 'a\nb'},
    {'action': 'text', 'text': "it's"}, {'action': 'text', 'text': ''},
    {'action': 'keyevent', 'key': 'POWER'}, {'action': 'unknown'}, [],
])
def test_ui_rejects_shell_metacharacters_extra_fields_and_bounds(ui_request):
    with pytest.raises((ValueError, TypeError)):
        operations.ui_arguments(ui_request)


def test_ui_known_actions_are_argument_lists():
    assert operations.ui_arguments({'action': 'tap', 'x': 0, 'y': 10000}) == ['input', 'tap', '0', '10000']
    assert operations.ui_arguments({'action': 'text', 'text': 'Hello world!'}) == ['input', 'text', "'Hello%sworld!'"]
    assert operations.ui_arguments({'action': 'keyevent', 'key': 'HOME'}) == ['input', 'keyevent', '3']
    assert operations.ui_arguments({'action': 'swipe', 'x1': 0, 'y1': 1, 'x2': 2, 'y2': 3, 'duration_ms': 500}) == ['input', 'swipe', '0', '1', '2', '3', '500']


def test_signed_file_roundtrip(service):
    payload = b'only within dedicated root\x00'
    assert service.request('POST', '/upload?path=file.bin', payload).status == 200
    result = service.request('GET', '/download?path=file.bin')
    assert result.status == 200
    assert result.body == payload


@pytest.mark.parametrize('path', ['../outside', '/absolute', 'a/../b', 'a\\b'])
def test_signed_file_traversal_rejected(service, path):
    from urllib.parse import quote
    target = '/download?path=' + quote(path, safe='')
    assert service.request('GET', target).status == 400
