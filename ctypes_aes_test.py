import unittest
import ctypes

clibrary = ctypes.CDLL("/home/fsdm/repos/aes-rijndael--block-cipher-assignment-2/rijndael.so");

class TestBlock(unittest.TestCase):
    def setUp(self) -> None:
        return super().setUp()
    # Encryption and decryption of a block of data using the Rijndael algorithm with 1
    # 28-bit key.
    def test_success(self):
        # 128-bit key
        key = b"Thats my Kung Fu"
        # 128-bit block
        block = b"Two One Nine Two"
        # 128-bit block
        cipher = b"\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A"
        # Encrypt the block
        encrypted = clibrary.encrypt_block(key, block)
        # Decrypt the block
        decrypted = clibrary.decrypt_block(key, encrypted)
        # Check if the decrypted block is equal to the original block
        self.assertEqual(decrypted, block)
        # Check if the encrypted block is equal to the cipher
        self.assertEqual(encrypted, cipher)
    def test_bad_key(self):
        # 128-bit key
        key = b"Thats my Kung Fu"
        # 128-bit block
        block = b"Two One Nine Two"
        # 128-bit block
        cipher = b"\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A"
        # Encrypt the block
        encrypted = clibrary.encrypt_block(key, block)
        # Decrypt the block
        decrypted = clibrary.decrypt_block(b"Thats my Kung Fu", encrypted)
        # Check if the decrypted block is equal to the original block
        self.assertNotEqual(decrypted, block)
        # Check if the encrypted block is equal to the cipher
        self.assertNotEqual(encrypted, cipher)
    def tearDown(self) -> None:
        return super().tearDown()

def run():
    unittest.main()
if __name__ == "__main__":
    run()

