import unittest
import ctypes

class TestSubBytes(unittest.TestCase):
    """
    Tests sub bytes
    """
    def setUp(self):
        self.rijndael = ctypes.CDLL("./rijndael.so")
        self.test_input = (ctypes.c_ubyte * 16)(*range(16))
        # Expected output for a valid scenario based on S-Box transformation
        self.test_expected_success_value = (ctypes.c_ubyte * 16)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)
        
        # Expected output for a failure scenario (with an intentional mismatch)
        self.expected_failure_output = (ctypes.c_ubyte * 16)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x00, 0x6f, 0xc5, 
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)

    def test_sub_bytes_success(self):
        self.rijndael.sub_bytes(self.test_input)
        for i in range(16):
            self.assertEqual(self.test_input[i], self.test_expected_success_value[i], "SubBytes transformation failed.")
        

    def test_sub_bytes_failure(self):
        self.rijndael.sub_bytes(self.test_input)
        with self.assertRaises(AssertionError):
            for i in range(16):
                self.assertEqual(self.test_input[i], self.expected_failure_output[i], "SubBytes transformation failed.")
    
    def test_sub_bytes_first_index(self):
        """Test that sub_bytes first index of S_BOX."""
        # Setup test input with all bytes set to 0x00
        test_input = (ctypes.c_ubyte * 16)(0x00)
        # Apply the sub_bytes transformation
        self.rijndael.sub_bytes(test_input)
        # Verify the transformation of the first byte (assuming S_BOX[0x00] = 0x63)
        self.assertEqual(test_input[0], 0x63, "SubBytes transformation failed.")
        
    def test_sub_bytes_last_index(self):
        """Test that sub_bytes last index of S_BOX."""
        # Setup test input with all bytes set to 0xFF
        test_input = (ctypes.c_ubyte * 16)(0xFF)
        # Apply the sub_bytes transformation
        self.rijndael.sub_bytes(test_input)
        # Verify the transformation of the first byte (assuming S_BOX[0xFF] = expected value)
        # Replace `expected_last_value` with the actual value from your S_BOX for 0xFF
        expected_last_value = 0x16  # Example value, adjust based on your S_BOX
        self.assertEqual(test_input[0], expected_last_value, "SubBytes transformation failed.")
    

class TestShiftRows(unittest.TestCase):
    def setUp(self):
        self.rijndael = ctypes.CDLL('./rijndael.so')
        self.test_input = (ctypes.c_ubyte * 16)(*[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.expected_after_shift = (ctypes.c_ubyte * 16)(*[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])

    def test_shift_rows_correctness(self):
        self.rijndael.shift_rows(self.test_input)
        for i in range(16):
            self.assertEqual(self.test_input[i], self.expected_after_shift[i], f"Byte {i} did not match expected value.")

    def test_shift_rows_first_row_unchanged(self):
        # Identifying the first row's elements before the shift
        original_first_row = [self.test_input[i] for i in range(0, 16, 4)]
        self.rijndael.shift_rows(self.test_input)
        # Identifying the first row's elements after the shift
        shifted_first_row = [self.test_input[i] for i in range(0, 16, 4)]
        self.assertEqual(original_first_row, shifted_first_row, "First row was altered.")

class TestInvertSubBytes(unittest.TestCase):
    def setUp(self):
        self.rijndael = ctypes.CDLL("./rijndael.so")
        self.test_input = (ctypes.c_ubyte * 16)(*range(16))
        # Expected output for a valid scenario based on the Inverse S-Box transformation
        self.test_expected_success_value = (ctypes.c_ubyte * 16)(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
        
        # Expected output for a failure scenario (with an intentional mismatch)
        self.expected_failure_output = (ctypes.c_ubyte * 16)(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xFF)  # Last byte changed intentionally

    def test_invert_sub_bytes_success(self):
        """Test the invert_sub_bytes function with a specific input."""
        # S_BOX from 0x00 to 0x0F
        transformed_sequence = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
        ]
        self.test_input = (ctypes.c_ubyte * 16)(*transformed_sequence)
        self.rijndael.invert_sub_bytes(self.test_input)
        # Expected output after inverting from 0x00 to 0x0F
        expected_sequence = (ctypes.c_ubyte * 16)(*range(16))
        for i in range(16):
            self.assertEqual(self.test_input[i], expected_sequence[i], "InvertSubBytes transformation failed.")


    def test_invert_sub_bytes_failure(self):
        """Test invert_sub_bytes with modified expected output."""
        self.rijndael.invert_sub_bytes(self.test_input)
        with self.assertRaises(AssertionError):
            for i in range(16):
                self.assertEqual(self.test_input[i], self.expected_failure_output[i], "InvertSubBytes transformation failed.")

    def test_invert_sub_bytes_first_index(self):
        """Test invert_sub_bytes inverts the first index of INV_S_BOX."""
        # Set to the output value of S_BOX[0x00] (0x63)
        test_input = (ctypes.c_ubyte * 16)(0x63)
        self.rijndael.invert_sub_bytes(test_input)
        # Check if it inverts back to 0x00
        self.assertEqual(test_input[0], 0x00, "InvertSubBytes transformation failed.")

    def test_invert_sub_bytes_last_index(self):
        """Test invert_sub_bytes inverts the last index of INV_S_BOX."""
        # Setthe output value of S_BOX[0xFF] (0x16)
        test_input = (ctypes.c_ubyte * 16)(0x16) 
        self.rijndael.invert_sub_bytes(test_input)
        # Check if it correctly inverts back to 0xFF
        self.assertEqual(test_input[0], 0xFF, "InvertSubBytes transformation failed.")

class TestInvertShiftRows(unittest.TestCase):
    def setUp(self):
        self.rijndael = ctypes.CDLL("./rijndael.so")
        # Initialize with a state that would result AFTER applying shift_rows
        # This is the state we expect AFTER shift_rows and BEFORE invert_shift_rows
        self.test_input = (ctypes.c_ubyte * 16)(
            0x00, 0x05, 0x0A, 0x0F,  # Row 0 remains unchanged
            0x04, 0x09, 0x0E, 0x03,  # Row 1 shifted right by 1 (undo left shift of 1)
            0x08, 0x0D, 0x02, 0x07,  # Row 2 shifted right by 2 (undo left shift of 2)
            0x0C, 0x01, 0x06, 0x0B)  # Row 3 shifted right by 3 (undo left shift of 3)

    def test_invert_shift_rows_correctness(self):
        # Expected output is the original state before shift_rows was applied
        expected_output = (ctypes.c_ubyte * 16)(*range(16))
        
        # Apply invert_shift_rows to the test input
        self.rijndael.invert_shift_rows(self.test_input)
        
        # Verify that each byte is correctly reverted to its original position
        for i in range(16):
            self.assertEqual(self.test_input[i], expected_output[i],
                             f"Byte {i} did not match expected value after invert_shift_rows.")

def run():
    unittest.main()

if __name__ == '__main__':
    unittest.main()


    # Before runing this test make sure you have compiled the shared object file
    # gcc -o rijndael.o rijndael.c
    # gcc -fPIC -shared -o rijndael.so rijndael.c