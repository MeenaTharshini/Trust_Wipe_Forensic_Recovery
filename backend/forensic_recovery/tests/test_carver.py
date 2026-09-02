import os
import shutil
import unittest
from carving.carver import FileCarver
from carving.signatures import DEFAULT_SIGNATURES

class TestFileCarver(unittest.TestCase):
    def setUp(self):
        self.test_output = "./test_recovered_tmp"
        self.carver = FileCarver(output_dir=self.test_output)

    def tearDown(self):
        if os.path.exists(self.test_output):
            shutil.rmtree(self.test_output)

    def test_png_carve(self):
        # Create buffer containing PNG header and footer
        fake_png = b"\x89PNG\x0D\x0A\x1A\x0A" + b"\x00" * 32 + b"IEND\xAE\x42\x60\x82"
        buf = b"RANDOM_NOISE" + fake_png + b"MORE_NOISE"
        
        results = self.carver.carve_buffer(buf, start_offset=0)
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["extension"], "png")
        self.assertEqual(results[0]["category"], "Images")

if __name__ == "__main__":
    unittest.main()
