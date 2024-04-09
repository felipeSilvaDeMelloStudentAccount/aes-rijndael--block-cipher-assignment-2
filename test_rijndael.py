import ctypes
import unittest


class RijndaelTestBase(unittest.TestCase):
    def setUp(self):
        self.BLOCK_SIZE = 16
        self.rijndael = ctypes.CDLL("./rijndael.so")
        self.test_input = (ctypes.c_ubyte * 16)(*range(16))

    def assertEqualByteArray(self, actual, expected, message="Byte array mismatch"):
        for i, (actual_byte, expected_byte) in enumerate(zip(actual, expected)):
            self.assertEqual(actual_byte, expected_byte,
                             f"{message} at index {i}: expected {expected_byte}, got {actual_byte}")


class TestSubBytes(RijndaelTestBase):
    def test_sub_bytes_success(self):
        test_expected_success_value = (ctypes.c_ubyte * 16)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)

        self.rijndael.sub_bytes(self.test_input)
        for i in range(16):
            self.assertEqual(self.test_input[i], test_expected_success_value[i], "SubBytes transformation failed.")

    def test_sub_bytes_failure(self):
        # Expected output for a failure scenario (with an intentional mismatch)
        expected_failure_output = (ctypes.c_ubyte * 16)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x00, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)
        self.rijndael.sub_bytes(self.test_input)
        with self.assertRaises(AssertionError):
            for i in range(16):
                self.assertEqual(self.test_input[i], expected_failure_output[i], "SubBytes transformation failed.")

    def test_sub_bytes_first_index(self):
        self.rijndael.sub_bytes(self.test_input)
        # Verify the transformation of the first byte (assuming S_BOX[0x00] = 0x63)
        self.assertEqual(self.test_input[0], 0x63, "SubBytes transformation failed.")

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


class TestMixSingleColumn(RijndaelTestBase):
    def test_mix_single_column(self):
        # Example column to mix
        column = (ctypes.c_ubyte * 4)(0xd4, 0xbf, 0x5d, 0x30)
        # Expected result after mixing the column
        expected_column = (ctypes.c_ubyte * 4)(0x04, 0x66, 0x81, 0xe5)

        # Call the wrapper function
        self.rijndael.mix_single_column(column)

        # Check if the mixed column matches the expected result
        for i, expected_value in enumerate(expected_column):
            self.assertEqual(column[i], expected_value,
                             f"Byte {i} mismatch: expected {hex(expected_value)}, got {hex(column[i])}")


class TestMixColumns(RijndaelTestBase):
    def test_mix_columns(self):
        # Example block before applying mix_columns
        block = (ctypes.c_ubyte * 16)(
            0xd4, 0xe0, 0xb8, 0x1e,
            0xbf, 0xb4, 0x41, 0x27,
            0x5d, 0x52, 0x11, 0x98,
            0x30, 0xae, 0xf1, 0xe5
        )
        # Expected block after applying mix_columns
        expected_block = (ctypes.c_ubyte * 16)(
            0x04, 0xe0, 0x48, 0x28,
            0x66, 0xcb, 0xf8, 0x06,
            0x81, 0x19, 0xd3, 0x26,
            0xe5, 0x9a, 0x7a, 0x4c
        )

        # Call the mix_columns function
        self.rijndael.mix_columns(ctypes.byref(block))

        # Check if the mixed block matches the expected result
        for i, expected_value in enumerate(expected_block):
            self.assertEqual(block[i], expected_value,
                             f"Byte {i} mismatch: expected {hex(expected_value)}, got {hex(block[i])}")


class TestShiftRows(RijndaelTestBase):
    def test_shift_rows_correctness(self):
        test_input = (ctypes.c_ubyte * 16)(*[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        expected_after_shift = (ctypes.c_ubyte * 16)(*[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
        self.rijndael.shift_rows(test_input)
        for i in range(16):
            self.assertEqual(test_input[i], expected_after_shift[i],
                             f"Byte {i} did not match expected value.")

    def test_shift_rows_first_row_unchanged(self):
        test_input = (ctypes.c_ubyte * 16)(*[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        expected_after_shift = (ctypes.c_ubyte * 16)(*[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
        # Identifying the first row's elements before the shift
        original_first_row = [test_input[i] for i in range(0, 16, 4)]
        self.rijndael.shift_rows(test_input)
        # Identifying the first row's elements after the shift
        shifted_first_row = [test_input[i] for i in range(0, 16, 4)]
        self.assertEqual(original_first_row, shifted_first_row, "First row was altered.")


class TestInvertSubBytes(RijndaelTestBase):
    def test_invert_sub_bytes_success(self):
        """Test the invert_sub_bytes function with specific input."""
        transformed_sequence = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
        ]
        test_input = (ctypes.c_ubyte * 16)(*transformed_sequence)
        expected_sequence = (ctypes.c_ubyte * 16)(*range(16))

        self.rijndael.invert_sub_bytes(ctypes.byref(test_input))
        self.assertEqualByteArray(test_input, expected_sequence)

    def test_invert_sub_bytes_failure(self):
        """Test invert_sub_bytes detects mismatches."""
        test_input = (ctypes.c_ubyte * 16)(*[0x63] * 16)  # Repeated 0x63 should not match the expected sequence
        expected_failure_output = (ctypes.c_ubyte * 16)(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xFF)  # Last byte intentionally incorrect for failure scenario

        self.rijndael.invert_sub_bytes(ctypes.byref(test_input))
        with self.assertRaises(AssertionError):
            self.assertEqualByteArray(test_input, expected_failure_output)

    def test_invert_sub_bytes_boundary_cases(self):
        """Test invert_sub_bytes boundary cases: first and last indexes of INV_S_BOX."""
        # First index case: S_BOX[0x00] -> 0x63 inverted should be 0x00
        test_input_first = (ctypes.c_ubyte * 16)(0x63)
        self.rijndael.invert_sub_bytes(ctypes.byref(test_input_first))
        self.assertEqual(test_input_first[0], 0x00, "InvertSubBytes first index transformation failed.")

        # Last index case: assuming S_BOX[0xFF] -> 0x16 inverted should be 0xFF
        test_input_last = (ctypes.c_ubyte * 16)(0x16)
        self.rijndael.invert_sub_bytes(ctypes.byref(test_input_last))
        self.assertEqual(test_input_last[0], 0xFF, "InvertSubBytes last index transformation failed.")


class TestInvertShiftRows(RijndaelTestBase):
    def test_invert_shift_rows_correctness(self):
        test_input = (ctypes.c_ubyte * 16)(
            0x00, 0x05, 0x0A, 0x0F,  # Row 0 remains unchanged
            0x04, 0x09, 0x0E, 0x03,  # Row 1 shifted right by 1 (undo left shift of 1)
            0x08, 0x0D, 0x02, 0x07,  # Row 2 shifted right by 2 (undo left shift of 2)
            0x0C, 0x01, 0x06, 0x0B)  # Row 3 shifted right by 3 (undo left shift of 3)
        # Expected output is the original state before shift_rows was applied
        expected_output = (ctypes.c_ubyte * 16)(*range(16))

        # Apply invert_shift_rows to the test input
        self.rijndael.invert_shift_rows(test_input)

        # Verify that each byte is correctly reverted to its original position
        for i in range(16):
            self.assertEqual(test_input[i], expected_output[i],
                             f"Byte {i} did not match expected value after invert_shift_rows.")


class TestXTIME(RijndaelTestBase):
    # Set up the test case
    def test_XTIME(self):
        self.rijndael.xtime_wrapper.argtypes = [ctypes.c_ubyte]
        self.rijndael.xtime_wrapper.restype = ctypes.c_ubyte
        self.test_cases = [
            (0x57, 0xAE),  # Typical case without needing to XOR with 0x1b
            (0x80, 0x1B),  # Case where XOR with 0x1b is needed
        ]
        for input_val, expected_output in self.test_cases:
            actual_output = self.rijndael.xtime_wrapper(ctypes.c_ubyte(input_val))
            self.assertEqual(actual_output, expected_output,
                             f"XTIME({hex(input_val)}) = {hex(actual_output)}, expected {hex(expected_output)}")


class TestInvMixColumns(RijndaelTestBase):
    def test_inv_mix_columns_correctness(self):
        test_input = (ctypes.c_ubyte * 16)(
            0x47, 0x40, 0xa3, 0x4c,
            0x37, 0xd4, 0x70, 0x9f,
            0x94, 0xe4, 0x3a, 0x42,
            0xed, 0xa5, 0xa6, 0xbc
        )
        # Expected output after applying inv_mix_columns
        expected_output = (ctypes.c_ubyte * 16)(
            0x87, 0xf2, 0x4d, 0x97,
            0x6e, 0x4c, 0x90, 0xec,
            0x46, 0xe7, 0x4a, 0xc3,
            0xa6, 0x8c, 0xd8, 0x95
        )

        # Apply inv_mix_columns to the test input
        self.rijndael.inv_mix_columns(test_input)

        # Verify that each byte is correctly transformed
        for i in range(16):
            self.assertEqual(test_input[i], expected_output[i],
                             f"Byte {i} did not match expected value after inv_mix_columns.")


class TestAddRoundKey(RijndaelTestBase):
    def test_add_round_key(self):
        # Test block and round key
        test_block = (ctypes.c_ubyte * self.BLOCK_SIZE)(*range(self.BLOCK_SIZE))
        # Round key is the inverse of the test block
        test_round_key = (ctypes.c_ubyte * self.BLOCK_SIZE)(*(15 - i for i in range(self.BLOCK_SIZE)))

        # Expected output after XORing test_block with test_round_key
        expected_output = (ctypes.c_ubyte * self.BLOCK_SIZE)(
            *(i ^ (15 - i) for i in range(self.BLOCK_SIZE)))

        # Apply the add_round_key function
        self.rijndael.add_round_key(test_block, test_round_key)

        # Assert that each byte in the modified block matches the expected output
        for i in range(self.BLOCK_SIZE):
            self.assertEqual(test_block[i], expected_output[i],
                             f"Byte {i} mismatch: expected {expected_output[i]}, got {test_block[i]}")


def run():
    unittest.main()


if __name__ == '__main__':
    unittest.main()

    # Before runing this test make sure you have compiled the shared object file
    # gcc -o rijndael.o rijndael.c
    # gcc -fPIC -shared -o rijndael.so rijndael.c
