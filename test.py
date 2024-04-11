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


class TestEncrypt(unittest.TestCase):
    def test_sub_bytes(self):
        plaintext_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        plaintext_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        subByte_matrices_c = c_aes.sub_bytes(plaintext_arr, 16)

        subByte_matrices_py = aes.sub_bytes(aes.bytes2matrix(plaintext_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_fail_sub_bytes(self):
        plaintext_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x12\x33\x11\x04\x08\x06\x63'
        plaintext_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        subByte_matrices_c = c_aes.sub_bytes(plaintext_arr, 16)

        subByte_matrices_py = aes.sub_bytes(aes.bytes2matrix(plaintext_py))

        self.assertNotEqual(list(plaintext_c), list(plaintext_py))

    def test_shift_rows(self):
        plaintext_c = b'\x34\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        plaintext_py = b'\x34\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        c_aes.shift_rows(plaintext_arr, 16)

        aes.shift_rows(aes.bytes2matrix(plaintext_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_expand_key(self):
        key = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        key_arr = (ctypes.c_ubyte * len(key))(*key)

        key_matrices_c = c_aes.expand_key(key_arr)

        c_bytes = bytes(key_matrices_c[:16])

        converted_c_bytes = aes.bytes2matrix(c_bytes)

        key_matrices_python = (aes.AES(key)._key_matrices)[0]

        self.assertEqual(converted_c_bytes, key_matrices_python)

    def test_mixColumns(self):
        plaintext_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'

        plaintext_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        c_aes.mix_columns(plaintext_arr)

        aes.mix_columns(aes.bytes2matrix(plaintext_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_inv_sub_bytes(self):
        plaintext_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'
        plaintext_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        subByte_matrices_c = c_aes.invert_sub_bytes(plaintext_arr, 16)

        subByte_matrices_py = aes.inv_sub_bytes(aes.bytes2matrix(plaintext_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_inv_shift_rows(self):
        plaintext_c = b'\x32\x14\x2E\x55\x33\x09\x46\x1A\x4A\x11\x13\x11\x04\x08\x06\x63'
        plaintext_py = b'\x32\x14\x2E\x55\x33\x09\x46\x1A\x4A\x11\x13\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        c_aes.invert_shift_rows(plaintext_arr, 16)

        aes.inv_shift_rows(aes.bytes2matrix(plaintext_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_inv_mixColumns(self):
        plaintext_c = b'\x32\x14\xAE\x56\x33\x09\x46\x1C\x4B\x11\x13\x11\x04\x08\x06\x63'

        plaintext_py = b'\x32\x14\xAE\x56\x33\x09\x46\x1C\x4B\x11\x13\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        c_aes.invert_mix_columns(plaintext_arr)

        aes.inv_mix_columns(aes.bytes2matrix(plaintext_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_fail_inv_mixColumns(self):
        plaintext_c = b'\x32\x13\xAE\x56\x33\x09\x46\x1C\x4B\x11\x13\x11\x04\x08\x06\x63'

        plaintext_py = b'\x31\x11\xAA\x57\x33\x09\x46\x1A\x4B\x12\x13\x11\x04\x09\x01\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)

        c_aes.invert_mix_columns(plaintext_arr)

        aes.inv_mix_columns(aes.bytes2matrix(plaintext_py))

        self.assertNotEqual(list(plaintext_c), list(plaintext_py))

    def test_add_round_key(self):
        plaintext_c = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        key_c = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        plaintext_py = b'\x32\x14\x2E\x56\x33\x09\x46\x1A\x4B\x11\x13\x11\x04\x08\x06\x63'
        key_py = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        plaintext_arr = (ctypes.c_ubyte * len(plaintext_c))(*plaintext_c)
        key_arr = (ctypes.c_ubyte * len(key_c))(*key_c)

        c_aes.add_round_key(plaintext_arr, key_arr, 0, 15)

        aes.add_round_key(aes.bytes2matrix(plaintext_py), aes.bytes2matrix(key_py))

        self.assertEqual(list(plaintext_c), list(plaintext_py))

    def test_c_aes_encrypt_block(self):
        plaintext = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'

        key = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        # Converting plaintext & key into ctypes arrays
        plaintext_arr = (ctypes.c_ubyte * len(plaintext))(*plaintext)
        key_arr = (ctypes.c_ubyte * len(key))(*key)

        # Calling the AES encrypt function in main.c
        encrypted_data = c_aes.aes_encrypt_block(plaintext_arr, key_arr)

        # Converting the encrypted data back to byte
        c_encrypted_bytes = bytes(encrypted_data[:16])

        py_encrypted_bytes = aes.AES(key).encrypt_block(plaintext)

        self.assertEqual(c_encrypted_bytes, py_encrypted_bytes)

    ''' 
        Testing AES-128 bit decrypt function
    '''

    def test_c_aes_decrypt_block(self):
        cipher_text = b'\x4b\x95\x86\x93\xb4\xe9\xc4\xeb\x92\xaf\xe8t\xb1\x40\xe0\xce'

        key = b'\x32\x14\x2E\x56\x43\x09\x46\x1B\x4B\x11\x33\x11\x04\x08\x06\x63'

        # Converting plaintext & key into ctypes arrays
        cipher_text_arr = (ctypes.c_ubyte * len(cipher_text))(*cipher_text)
        key_arr = (ctypes.c_ubyte * len(key))(*key)

        # Calling the AES decrypt function in main.c
        decrypted_data = c_aes.aes_decrypt_block(cipher_text_arr, key_arr)

        # Converting the decrypted data back to byte
        c_decrypted_bytes = bytes(decrypted_data[:16])

        py_decrypted_bytes = aes.AES(key).decrypt_block(cipher_text)

        self.assertEqual(c_decrypted_bytes, py_decrypted_bytes)


if __name__ == '__main__':
    unittest.main()
