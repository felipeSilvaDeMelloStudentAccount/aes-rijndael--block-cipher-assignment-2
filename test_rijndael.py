import ctypes
import unittest

import aes.aes as aes

# Load the shared library into ctypes
c_aes = ctypes.CDLL('./rijndael.so')

# Set the argument types for the functions in the shared library
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

# Set the return types for the functions in the shared library
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


# Test cases for the AES implementation
class TestSubBytes(unittest.TestCase):
    # Test the SubBytes transformation
    def test_sub_bytes(self):
        test_block = bytearray([0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
                                0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34])
        expected_block = bytearray([aes.s_box[b] for b in test_block])
        # Convert the input block to a ctypes array of bytes
        c_test_block = (ctypes.c_ubyte * len(test_block))(*test_block)
        # Call the SubBytes transformation from the C shared library
        c_aes.sub_bytes(c_test_block, len(test_block))
        # Convert the result back to a bytearray
        c_result_block = bytearray(c_test_block)
        # Compare the result with the expected output
        self.assertEqual(c_result_block, expected_block,
                         "The SubBytes transformation did not match the expected output.")

    def test_compare_sub_bytes(self):
        test_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        # Convert the input block to a ctypes array of bytes
        text_array = (ctypes.c_ubyte * len(test_c))(*test_c)
        # Call the SubBytes transformation from the C shared library
        c_aes.sub_bytes(text_array, 16)
        # Call the SubBytes transformation from the python implementation
        aes.sub_bytes(aes.bytes2matrix(text_py))
        # Compare the C implementation with the python implementation
        self.assertEqual(list(test_c), list(text_py))

    def test_fail_sub_bytes(self):
        text_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x12\x33\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.sub_bytes(text_array, 16)
        aes.sub_bytes(aes.bytes2matrix(text_py))
        self.assertNotEqual(list(text_c), list(text_py))


class TestShiftRows(unittest.TestCase):
    def test_compare_shift_rows(self):
        text_c = b'\x34\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x34\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.shift_rows(text_array, 16)
        aes.shift_rows(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))

    def test_fail_shift_rows(self):
        text_c = b'\x34\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x34\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.shift_rows(text_array, 16)
        aes.shift_rows(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))


class TestMixColumns(unittest.TestCase):

    def test_compare_mix_columns(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.mix_columns(text_array)
        aes.mix_columns(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))

    def test_fail_mix_columns(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.mix_columns(text_array)
        aes.mix_columns(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))


class TestInvertSubBytes(unittest.TestCase):
    def test_compare_invert_sub_bytes(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.invert_sub_bytes(text_array, 16)
        aes.inv_sub_bytes(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))

    def test_fail_invert_sub_bytes(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.invert_sub_bytes(text_array, 16)
        aes.inv_sub_bytes(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))


class TestInvertShiftRows(unittest.TestCase):
    def test_compare_invert_shift_rows(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.invert_shift_rows(text_array, 16)
        aes.inv_shift_rows(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))

    def test_fail_invert_shift_rows(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.invert_shift_rows(text_array, 16)
        aes.inv_shift_rows(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))


class TestInvertMixColumns(unittest.TestCase):

    def test_compare_invert_mix_columns(self):
        text_c = b'\x32\x14\xAE\x56\x33\x09\x46\x1C\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\xAE\x56\x33\x09\x46\x1C\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.invert_mix_columns(text_array)
        aes.inv_mix_columns(aes.bytes2matrix(text_py))
        self.assertEqual(list(text_c), list(text_py))

    def test_fail_invert_mix_columns(self):
        text_c = b'\x32\x13\xAE\x56\x33\x09\x46\x1C\x4B\x11\x13\x11\x04\x08\x06\x63'
        text_py = b'\x31\x11\xAA\x57\x33\x09\x46\x1A\x4B\x12\x13\x11\x04\x09\x01\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        c_aes.invert_mix_columns(text_array)
        aes.inv_mix_columns(aes.bytes2matrix(text_py))
        self.assertNotEqual(list(text_c), list(text_py))


class TestAddRoundKey(unittest.TestCase):

    def test_compare_add_round_key(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        key_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        key_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        key_arr = (ctypes.c_ubyte * len(key_c))(*key_c)
        c_aes.add_round_key(text_array, key_arr, 0, 15)
        aes.add_round_key(aes.bytes2matrix(text_py), aes.bytes2matrix(key_py))
        self.assertEqual(list(text_c), list(text_py))

    def test_fail_add_round_key(self):
        text_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        key_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        text_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        key_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        text_array = (ctypes.c_ubyte * len(text_c))(*text_c)
        key_arr = (ctypes.c_ubyte * len(key_c))(*key_c)
        c_aes.add_round_key(text_array, key_arr, 0, 15)
        aes.add_round_key(aes.bytes2matrix(text_py), aes.bytes2matrix(key_py))


class TestExpandKey(unittest.TestCase):
    def test_expand_key(self):
        key = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        key_arr = (ctypes.c_ubyte * len(key))(*key)
        key_matrices_c = c_aes.expand_key(key_arr)
        c_bytes = bytes(key_matrices_c[:16])
        converted_c_bytes = aes.bytes2matrix(c_bytes)
        key_matrices_python = (aes.AES(key)._key_matrices)[0]
        self.assertEqual(converted_c_bytes, key_matrices_python)


class TestEncrypt(unittest.TestCase):

    def test_c_aes_encrypt_block(self):
        # Test the encryption of a single block
        plaintext = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        # The key for the encryption
        key = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        # Convert the input block to a ctypes array of bytes
        text_array = (ctypes.c_ubyte * len(plaintext))(*plaintext)
        # Convert the key to a ctypes array of bytes
        key_arr = (ctypes.c_ubyte * len(key))(*key)
        # Call the encryption function from the C shared library
        encrypted_data = c_aes.aes_encrypt_block(text_array, key_arr)
        # Convert the result back to a bytearray
        c_encrypted_bytes = bytes(encrypted_data[:16])
        # Encrypt the plaintext using the python implementation
        py_encrypted_bytes = aes.AES(key).encrypt_block(plaintext)
        # Compare the C implementation with the python implementation
        self.assertEqual(c_encrypted_bytes, py_encrypted_bytes)


class TestDecrypt(unittest.TestCase):

    def test_c_aes_decrypt_block(self):
        # Test the decryption of a single block
        cipher_text = b'\x4b\x95\x86\x93\xb4\xe9\xc4\xeb\x92\xaf\xe8t\xb1\x40\xe0\xce'
        # The key for the decryption
        key = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        # Convert the input block to a ctypes array of bytes
        cipher_text_arr = (ctypes.c_ubyte * len(cipher_text))(*cipher_text)
        # Convert the key to a ctypes array of bytes
        key_arr = (ctypes.c_ubyte * len(key))(*key)
        # Call the decryption function from the C shared library
        decrypted_data = c_aes.aes_decrypt_block(cipher_text_arr, key_arr)
        # Convert the result back to a bytearray
        c_decrypted_bytes = bytes(decrypted_data[:16])
        # Decrypt the cipher text using the python implementation
        py_decrypted_bytes = aes.AES(key).decrypt_block(cipher_text)
        # Compare the C implementation with the python implementation
        self.assertEqual(c_decrypted_bytes, py_decrypted_bytes)


def run():
    unittest.main()


if __name__ == '__main__':
    unittest.main()

    # Before runing this test make sure you have compiled the shared object file
    # gcc -o rijndael.o rijndael.c
    # gcc -fPIC -shared -o rijndael.so rijndael.c
