"""Module containing a few tests for this module"""
import unittest
import lib as sid


class Testsid(unittest.TestCase):
    """Class for testing sid"""

    sid_null = "S-1-0-0"
    sid_sample = "S-1-5-21-2127521184-1604012920-1887927527-72713"
    sid_null_bin = bytearray(b"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    sid_sample_bin = bytearray(
        b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa0e\xcf~xK\x9b_\xe7|\x87p\t\x1c\x01\x00"
    )
    sid_null_b64 = b"AQEAAAAAAAAAAAAA"
    sid_sample_b64 = b"AQUAAAAAAAUVAAAAoGXPfnhLm1/nfIdwCRwBAA=="

    def test_init_string(self):
        """Test creating sids from strings"""
        self.assertEqual(self.sid_null, str(sid.sid(self.sid_null)))
        self.assertEqual(self.sid_sample, str(sid.sid(self.sid_sample)))

    def test_init_base64(self):
        """Test creating sids from base64"""
        self.assertEqual(self.sid_null, str(sid.sid(self.sid_null_b64, sid.SID_BASE64)))
        self.assertEqual(
            self.sid_sample, str(sid.sid(self.sid_sample_b64, sid.SID_BASE64))
        )

    def test_init_binary(self):
        """Test creating sids from binary"""
        self.assertEqual(self.sid_null, str(sid.sid(self.sid_null_bin, sid.SID_BINARY)))
        self.assertEqual(
            self.sid_sample, str(sid.sid(self.sid_sample_bin, sid.SID_BINARY))
        )

    def test_ldap(self):
        """Test ldap filter form of sid"""
        sid_null_ldap = "\\01\\01\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00"
        sid_sample_ldap = "\\01\\05\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00\\a0\\65\\cf\\7e\\78\\4b\\9b\\5f\\e7\\7c\\87\\70\\09\\1c\\01\\00"
        self.assertEqual(sid_null_ldap, sid.sid(self.sid_null).ldap())
        self.assertEqual(sid_sample_ldap, sid.sid(self.sid_sample).ldap())

    def test_binary(self):
        """Test binary form of sid"""
        self.assertEqual(self.sid_null_bin, sid.sid(self.sid_null).binary())
        self.assertEqual(self.sid_sample_bin, sid.sid(self.sid_sample).binary())

    def test_base64(self):
        """Test base64 form of sid"""
        self.assertEqual(self.sid_null_b64, sid.sid(self.sid_null).base64())
        self.assertEqual(self.sid_sample_b64, sid.sid(self.sid_sample).base64())


if __name__ == "__main__":
    unittest.main()
