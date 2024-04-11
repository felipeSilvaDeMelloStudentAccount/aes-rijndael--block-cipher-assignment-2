import ctypes
import unittest

import aes.aes as aes

# importing .so file after building AES in C using makefile
c_aes = ctypes.CDLL('./rijndael.so')
c_aes.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
c_aes.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
c_aes.invert_sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
c_aes.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
c_aes.invert_shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
c_aes.add_round_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
                                ctypes.c_int]
c_aes.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
c_aes.invert_mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

# the below line sets the response type for the aes_encrypt_block function
c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
c_aes.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)
c_aes.sub_bytes.restype = ctypes.c_voidp
c_aes.invert_sub_bytes.restype = ctypes.c_voidp
c_aes.shift_rows.restype = ctypes.c_voidp
c_aes.invert_shift_rows.restype = ctypes.c_voidp
c_aes.add_round_key.restype = ctypes.c_voidp
c_aes.mix_columns.restype = ctypes.c_voidp
c_aes.invert_mix_columns.restype = ctypes.c_voidp


class RijndaelTestBase(unittest.TestCase):
    def setUp(self):
        self.BLOCK_SIZE = 16
        self.plaintext_c = (ctypes.c_ubyte * self.BLOCK_SIZE)(*range(self.BLOCK_SIZE))
        self.c_aes = c_aes

    def assertEqualByteArray(self, actual, expected, message="Byte array mismatch"):
        self.assertEqual(len(actual), len(expected), f"{message} - array length differs")
        for i, (actual_byte, expected_byte) in enumerate(zip(actual, expected)):
            self.assertEqual(actual_byte, expected_byte,
                             f"{message} at index {i}: expected {expected_byte}, got {actual_byte}")


class TestSubBytes(RijndaelTestBase):

    def test_sub_bytes(self):
        plaintext_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        plaintext_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)
        self.c_aes.sub_bytes(plaintext_arr, len(plaintext_c))  # Assuming this modifies the array in place

        # Assuming aes.sub_bytes() returns the modified matrix directly
        expected_matrix = aes.sub_bytes(aes.bytes2matrix(plaintext_py))
        expected_bytes = aes.matrix2bytes(expected_matrix)
        self.assertEqualByteArray(plaintext_arr, expected_bytes)


    def test_sub_bytes_failure(self):
        plaintext_c = (ctypes.c_ubyte * self.BLOCK_SIZE)(*range(self.BLOCK_SIZE))
        self.c_aes.sub_bytes(plaintext_c, self.BLOCK_SIZE)  # Perform the sub_bytes operation

        # Expected output for a failure scenario (with an intentional mismatch for demonstration)
        expected_failure_output = (ctypes.c_ubyte * self.BLOCK_SIZE)(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x00, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76)

        mismatch_found = False
        for i in range(self.BLOCK_SIZE):
            if plaintext_c[i] != expected_failure_output[i]:
                mismatch_found = True
                break

        self.assertTrue(mismatch_found, "Expected a mismatch in the SubBytes transformation, but it matched.")



# class TestShiftRows(RijndaelTestBase):
#     def test_shift_rows_correctness(self):
#         test_input = (ctypes.c_ubyte * self.BLOCK_SIZE)(*[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
#         expected_after_shift = (ctypes.c_ubyte * self.BLOCK_SIZE)(
#             *[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
#         self.rijndael.shift_rows(test_input)
#         for i in range(self.BLOCK_SIZE):
#             self.assertEqual(test_input[i], expected_after_shift[i],
#                              f"Byte {i} did not match expected value.")
#
#     def test_shift_rows_first_row_unchanged(self):
#         test_input = (ctypes.c_ubyte * self.BLOCK_SIZE)(*[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
#         expected_after_shift = (ctypes.c_ubyte * self.BLOCK_SIZE)(
#             *[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
#         # Identifying the first row's elements before the shift
#         original_first_row = [test_input[i] for i in range(0, self.BLOCK_SIZE, 4)]
#         self.rijndael.shift_rows(test_input)
#         # Identifying the first row's elements after the shift
#         shifted_first_row = [test_input[i] for i in range(0, self.BLOCK_SIZE, 4)]
#         self.assertEqual(original_first_row, shifted_first_row, "First row was altered.")
#
#
# class TestInvertSubBytes(RijndaelTestBase):
#
#     def test_invert_sub_bytes_failure(self):
#         """Test invert_sub_bytes detects mismatches."""
#         test_input = (ctypes.c_ubyte * self.BLOCK_SIZE)(
#             *[0x63] * self.BLOCK_SIZE)  # Repeated 0x63 should not match the expected sequence
#         expected_failure_output = (ctypes.c_ubyte * self.BLOCK_SIZE)(
#             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
#             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xFF)  # Last byte intentionally incorrect for failure scenario
#
#         self.rijndael.invert_sub_bytes(ctypes.byref(test_input))
#         with self.assertRaises(AssertionError):
#             self.assertEqualByteArray(test_input, expected_failure_output)
#
#
# class TestInvertShiftRows(RijndaelTestBase):
#     def test_invert_shift_rows_correctness(self):
#         test_input = (ctypes.c_ubyte * self.BLOCK_SIZE)(
#             0x00, 0x05, 0x0A, 0x0F,  # Row 0 remains unchanged
#             0x04, 0x09, 0x0E, 0x03,  # Row 1 shifted right by 1 (undo left shift of 1)
#             0x08, 0x0D, 0x02, 0x07,  # Row 2 shifted right by 2 (undo left shift of 2)
#             0x0C, 0x01, 0x06, 0x0B)  # Row 3 shifted right by 3 (undo left shift of 3)
#         # Expected output is the original state before shift_rows was applied
#         expected_output = (ctypes.c_ubyte * self.BLOCK_SIZE)(*range(self.BLOCK_SIZE))
#
#         # Apply invert_shift_rows to the test input
#         self.rijndael.invert_shift_rows(test_input)
#
#         # Verify that each byte is correctly reverted to its original position
#         for i in range(self.BLOCK_SIZE):
#             self.assertEqual(test_input[i], expected_output[i],
#                              f"Byte {i} did not match expected value after invert_shift_rows.")
#
#
# class TestExpandKey(RijndaelTestBase):
#     def test_expand_key_correctness(self):
#         # Sample 128-bit AES key (16 bytes)
#         self.sample_key = (ctypes.c_ubyte * 16)(0x2b, 0x7e, 0x15, 0x16,
#                                                 0x28, 0xae, 0xd2, 0xa6,
#                                                 0xab, 0xf7, 0x15, 0x88,
#                                                 0x09, 0xcf, 0x4f, 0x3c)
#         expanded_key = self.rijndael.expand_key(ctypes.byref(self.sample_key))
#         # Verify that the expanded key starts with the original key
#         for i in range(self.BLOCK_SIZE):
#             self.assertEqual(self.sample_key[i], expanded_key.contents[i], f"Mismatch at byte {i} of expanded key.")


def run():
    unittest.main()


if __name__ == '__main__':
    unittest.main()

    # Before runing this test make sure you have compiled the shared object file
    # gcc -o rijndael.o rijndael.c
    # gcc -fPIC -shared -o rijndael.so rijndael.c
