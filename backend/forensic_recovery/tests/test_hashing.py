test_hashing.py:
import hashlib
import unittest
from pathlib import Path

from forensic_recovery.acquisition.hashing import sha256_file

class TestHashing(unittest.TestCase):

    def test_hash(self):
        test_file = Path("test_hash_temp.bin")
        test_file.write_bytes(b"hello")

        try:
            expected = hashlib.sha256(b"hello").hexdigest()
            actual = sha256_file(test_file)

            self.assertEqual(actual, expected)
        finally:
            if test_file.exists():
                test_file.unlink()


if __name__ == "__main__":
    unittest.main()