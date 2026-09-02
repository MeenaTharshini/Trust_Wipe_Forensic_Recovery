import unittest
from acquisition.hashing import CryptographicHasher

class TestCryptographicHasher(unittest.TestCase):
    def test_bytes_hashing(self):
        sample = b"TrustWipe Forensic Engine Data"
        hashes = CryptographicHasher.calculate_bytes_hashes(sample)
        self.assertIn("sha256", hashes)
        self.assertIn("md5", hashes)
        self.assertIn("sha1", hashes)
        self.assertEqual(hashes["size_bytes"], len(sample))

if __name__ == "__main__":
    unittest.main()
