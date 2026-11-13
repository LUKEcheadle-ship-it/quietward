"""Real temporary filesystem transactions; no services or user-profile installs."""
from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import venv

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('installer_package', ROOT / 'scripts/installer_package.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class InstallerPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'version').write_text('new')
        self.site = self.root / 'site'
        self.site.mkdir()
        self.destination = self.site / 'quietward'
        self.destination.mkdir()
        (self.destination / 'version').write_text('old')

    def version(self):
        return (self.destination / 'version').read_text()

    def replace(self, validator=lambda path: None):
        helper.replace_package(self.source, self.destination, validator)

    def assert_clean(self):
        self.assertEqual(sorted(p.name for p in self.site.iterdir()), ['quietward'])

    def test_success_validates_promoted_package_before_discarding_backup(self):
        def validate(path):
            self.assertEqual(path, self.destination)
            self.assertEqual(self.version(), 'new')
            self.assertEqual((self.site / '.quietward-package-backup/version').read_text(), 'old')
        self.replace(validate)
        self.assertEqual(self.version(), 'new')
        self.assert_clean()

    def test_copy_failure_preserves_original(self):
        def failed_copy(source, destination, **kwargs):
            destination.mkdir()
            (destination / 'partial').write_text('partial')
            raise OSError('injected copy failure')
        with patch.object(helper.shutil, 'copytree', side_effect=failed_copy):
            with self.assertRaises(OSError): self.replace()
        self.assertEqual(self.version(), 'old')
        self.assert_clean()

    def test_validation_failure_restores_original(self):
        with self.assertRaisesRegex(RuntimeError, 'validation'):
            self.replace(lambda path: (_ for _ in ()).throw(RuntimeError('validation failure')))
        self.assertEqual(self.version(), 'old')
        self.assert_clean()

    def test_promotion_failure_restores_original(self):
        original = Path.rename
        def rename(path, target):
            if path.name == 'quietward' and path.parent.name.startswith('.quietward-package-stage-'):
                raise OSError('promotion failure')
            return original(path, target)
        with patch.object(Path, 'rename', rename):
            with self.assertRaisesRegex(OSError, 'promotion'): self.replace()
        self.assertEqual(self.version(), 'old')
        self.assert_clean()

    def test_failed_restore_retains_backup_and_blocks_retry(self):
        original = Path.rename
        def rename(path, target):
            if path.name == '.quietward-package-backup': raise OSError('restore failed')
            return original(path, target)
        with patch.object(Path, 'rename', rename):
            with self.assertRaisesRegex(OSError, 'restore failed'):
                self.replace(lambda path: (_ for _ in ()).throw(RuntimeError('validation failure')))
        self.assertEqual((self.site / '.quietward-package-backup/version').read_text(), 'old')
        self.assertTrue((self.site / '.quietward-package-lock').is_dir())
        with self.assertRaisesRegex(ValueError, 'backup'): self.replace()

    def test_first_install_validation_failure_leaves_no_partial_install(self):
        helper.shutil.rmtree(self.destination)
        with self.assertRaises(RuntimeError):
            self.replace(lambda path: (_ for _ in ()).throw(RuntimeError('validation failure')))
        self.assertEqual(list(self.site.iterdir()), [])

    def test_existing_lock_refuses_without_touching_package_or_lock(self):
        lock = self.site / '.quietward-package-lock'
        lock.mkdir()
        with self.assertRaises(FileExistsError): self.replace()
        self.assertTrue(lock.is_dir())
        self.assertEqual(self.version(), 'old')

    def test_source_link_is_rejected_before_original_changes(self):
        try: (self.source / 'linked').symlink_to(self.destination, target_is_directory=True)
        except OSError: self.skipTest('symlink creation unavailable')
        with self.assertRaisesRegex(ValueError, 'links'): self.replace()
        self.assertEqual(self.version(), 'old')
        self.assert_clean()

    def test_destination_link_is_rejected_without_touching_target(self):
        outside = self.root / 'outside'
        self.destination.rename(outside)
        try: self.destination.symlink_to(outside, target_is_directory=True)
        except OSError: self.skipTest('symlink creation unavailable')
        with self.assertRaisesRegex(ValueError, 'links'): self.replace()
        self.assertEqual((outside / 'version').read_text(), 'old')

    def test_overlapping_source_refused(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            helper.replace_package(self.destination, self.destination, lambda path: None)
        self.assertEqual(self.version(), 'old')

    def test_lexical_parent_alias_cannot_bypass_overlap_check(self):
        child = self.destination / 'child'
        child.mkdir()
        with self.assertRaisesRegex(ValueError, 'overlap'):
            helper.replace_package(child / '..', self.destination, lambda path: None)
        self.assertEqual(self.version(), 'old')

    def test_exact_python_identity_and_sibling_prefix_rejection(self):
        environment = self.root / 'venv'
        scripts = environment / 'Scripts'
        scripts.mkdir(parents=True)
        python = scripts / 'python.exe'
        python.write_bytes(b'synthetic executable identity only')
        helper.validate_process(environment, python)
        for relative in ('ScriptsOther/python.exe', 'Scripts/other.exe', 'Scripts/sub/python.exe'):
            path = environment / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic')
            with self.subTest(path=relative), self.assertRaises(ValueError):
                helper.validate_process(environment, path)
        with self.assertRaises(ValueError): helper.validate_process(environment, Path('python.exe'))

    def test_process_link_rejected(self):
        environment = self.root / 'venv'
        scripts = environment / 'Scripts'
        scripts.mkdir(parents=True)
        outside = self.root / 'python.exe'
        outside.write_bytes(b'synthetic')
        try: (scripts / 'python.exe').symlink_to(outside)
        except OSError: self.skipTest('symlink creation unavailable')
        with self.assertRaisesRegex(ValueError, 'links'):
            helper.validate_process(environment, scripts / 'python.exe')

    def test_real_isolated_interpreter_install_and_bad_upgrade_rollback(self):
        environment = self.root / 'real-venv'
        venv.EnvBuilder(with_pip=False).create(environment)
        python = environment / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
        site = Path(subprocess.check_output([str(python), '-I', '-c', 'import sysconfig;print(sysconfig.get_paths()["purelib"])'], text=True).strip())
        target = site / 'quietward'
        validate = lambda path: helper.validate_installed(python, path)
        helper.replace_package(ROOT / 'src/quietward', target, validate)
        original = (target / '__main__.py').read_bytes()
        (self.source / '__init__.py').write_text('')
        (self.source / '__main__.py').write_text('raise SystemExit(47)')
        with self.assertRaises(subprocess.CalledProcessError):
            helper.replace_package(self.source, target, validate)
        self.assertEqual((target / '__main__.py').read_bytes(), original)
        validate(target)

    def test_powershell_delegates_before_process_stop_and_state_updates(self):
        source = (ROOT / 'scripts/install_windows_preview.ps1').read_text()
        self.assertNotIn('.StartsWith($ExpectedPrefix)', source)
        self.assertLess(source.index('"validate-process"'), source.index('Stop-Process -Id'))
        self.assertLess(source.index('$Python = Resolve-Python'), source.index('\nStop-InstalledQuietWard\n'))
        self.assertIn('if ($LASTEXITCODE -ne 0)', source[source.index('"validate-process"'):source.index('Stop-Process -Id')])
        self.assertNotIn('Remove-Item -LiteralPath $InstalledPackage', source)
        self.assertLess(source.index('replace-package'), source.index("DELETE FROM metadata"))


if __name__ == '__main__': unittest.main()
