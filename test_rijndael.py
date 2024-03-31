import unittest
import ctypes

class TestSubBytes(unittest.TestCase):
    """
    Tests sub bytes
    """
    def setUp(self):
        self.rijndael = ctypes.CDLL("/home/fsdm/repos/aes-rijndael--block-cipher-assignment-2/rijndael.so")
        self.test_input = (ctypes.c_ubyte * 16)(*range(16))
        # Expected value for a valid scenerio
        self.test_expected_success_value = (ctypes.c_ubyte * 16)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)
        
        # Intentionally incorrect expected output for a failure scenario
        self.expected_failure_output = (ctypes.c_ubyte * 16)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x00, 0x6f, 0xc5, # Note the intentional error here
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)

    def test_sub_bytes_success(self):
        self.rijndael.sub_bytes(self.test_input)
        for i in range(16):
            self.assertEqual(self.test_input[i], self.test_expected_success_value[i], "SubBytes transformation failed on success scenario.")
        

    def test_sub_bytes_failure(self):
        self.rijndael.sub_bytes(self.test_input)
        with self.assertRaises(AssertionError):
            for i in range(16):
                self.assertEqual(self.test_input[i], self.expected_failure_output[i], "SubBytes transformation failed on failure scenario.")

    def tearDown(self):
        pass

def run():
    unittest.main()

if __name__ == '__main__':
    unittest.main()