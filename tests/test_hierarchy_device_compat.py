"""ADB transport regression tests; no device or network is accessed."""
import shlex

import pytest

from http_ctl import operations


@pytest.mark.parametrize('mode', ['legacy_join', 'modern_escape'])
def test_exec_out_uses_one_complete_command_across_adb_argument_modes(monkeypatch, mode):
    calls = []

    def run(argv, timeout, **kwargs):
        assert argv[:4] == ['/test/adb', '-s', 'localhost:5555', 'exec-out']
        # Legacy clients join arguments; modern clients preserve argv quoting
        # when there is more than one argument. A single command bypasses both.
        args = argv[4:]
        wire = (' '.join(args) if mode == 'legacy_join' or len(args) == 1
                else ' '.join(shlex.quote(arg) for arg in args))
        parsed = shlex.split(wire)
        assert parsed[:2] == ['sh', '-c']
        assert len(parsed) == 3
        script = parsed[2]
        assert not script.startswith("'umask")
        calls.append(script)
        return (0, b'<hierarchy/>' if len(calls) == 1 else b'HTTP_CTL_UI_CLEANUP_OK\n', b'', False, False)

    monkeypatch.setattr(operations, 'run_bounded', run)
    assert operations.ui_hierarchy('/test/adb') == b'<hierarchy/>'
    assert calls[0].startswith('umask 077\n')
    assert calls[1].endswith("printf 'HTTP_CTL_UI_CLEANUP_OK\\n'")


@pytest.mark.parametrize('output', [b'', b'sh: inaccessible or not found\n',
    b'HTTP_CTL_UI_CLEANUP_OK', b'noise\nHTTP_CTL_UI_CLEANUP_OK\n',
    b'HTTP_CTL_UI_CLEANUP_OK\nnoise', b'HTTP_CTL_UI_CLEANUP_OK\n\n'])
def test_cleanup_requires_exact_success_even_with_host_exit_zero(monkeypatch, output):
    results = iter([(0, b'<hierarchy/>', b'', False, False),
                    (0, output, b'', False, False)])
    monkeypatch.setattr(operations, 'run_bounded', lambda *a, **kw: next(results))
    with pytest.raises(ValueError, match='hierarchy cleanup unavailable'):
        operations.ui_hierarchy('/test/adb')


@pytest.mark.parametrize('size', [0, 1, 1048576, 1048577])
def test_xml_file_size_checked_before_reading(monkeypatch, tmp_path, size):
    import subprocess

    scripts = []

    def run(argv, *args, **kwargs):
        scripts.append(shlex.split(argv[-1])[2])
        return (0, b'<hierarchy/>' if len(scripts) == 1 else b'HTTP_CTL_UI_CLEANUP_OK\n', b'', False, False)

    monkeypatch.setattr(operations, 'run_bounded', run)
    operations.ui_hierarchy('/test/adb')
    main = scripts[0]
    assert 'ulimit' not in main  # ART runtime files must not inherit an XML cap.
    # Execute only the fixed post-dump file checks against a private local file.
    # Neither Android, ADB, nor UIAutomator can run in this test.
    check = main[main.index('test -f "$d/hierarchy.xml"'):]
    assert check.index('test ! -L') < check.index('stat -c %s') < check.index('cat ')
    (tmp_path / 'hierarchy.xml').write_bytes(b'x' * size)
    result = subprocess.run(['/bin/sh', '-c', 'd=' + shlex.quote(str(tmp_path)) + '\n' + check],
                            capture_output=True, timeout=3)
    if 0 < size <= operations.MAX_HIERARCHY:
        assert result.returncode == 0
        assert len(result.stdout) == size
    else:
        assert result.returncode != 0
        assert result.stdout == b''
