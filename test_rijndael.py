import unittest
import ctypes

class TestSubBytes(unittest.TestCase):
    """
    Tests sub bytes
    """
    def setUp(self):
        self.rijndael = ctypes.CDLL("./rijndael.so")
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

class TestShiftRows(unittest.TestCase):
    def setUp(self):
        self.rijndael = ctypes.CDLL('./rijndael.so')
        self.test_input = (ctypes.c_ubyte * 16)(*[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.expected_after_shift = (ctypes.c_ubyte * 16)(*[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])

    def test_shift_rows_correctness(self):
        self.rijndael.shift_rows(self.test_input)
        for i in range(16):
            self.assertEqual(self.test_input[i], self.expected_after_shift[i], f"Byte {i} did not match expected value after shift_rows.")

    def test_shift_rows_first_row_unchanged(self):
        # Correctly identifying the first row's elements before the shift
        original_first_row = [self.test_input[i] for i in range(0, 16, 4)]
        self.rijndael.shift_rows(self.test_input)
        # Correctly identifying the first row's elements after the shift
        shifted_first_row = [self.test_input[i] for i in range(0, 16, 4)]
        self.assertEqual(original_first_row, shifted_first_row, "First row was altered by shift_rows when it should remain unchanged.")



def run():
    unittest.main()

if __name__ == '__main__':
    unittest.main()


    # Before runing this test make sure you have compiled the shared object file
    # gcc -o rijndael.o rijndael.c
    # gcc -fPIC -shared -o rijndael.so rijndael.c