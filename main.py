#!/usr/bin/python

"""
BlackBox - A fast stream encrpyter/decrypter.

A robust, fast, GDPR compliant, no-fix-key (autokey) encrypter with remote controllable decryption.

* GDPR data at rest     - yes, compliant
* GDPR data in transit  - yes, compliant
* GDPR data protection over 'data drop' to legal user remote machine - yes, compliant
       using CryptoPlayer - A safe online/offline decrypter and player, (C) 2022 by Mariano Mancini
"""

__author__ = "Mariano Mancini"
__copyright__ = "Copyright 2022, Mariano Mancini"
__credits__ = ["Yaqub al-Kindi, C.E. Shannon, A.M. Turing "]
__license__ = "PRIVATE"
__version__ = "1.0.0"
__maintainer__ = "Mariano Mancini"
__email__ = "qhawaq@gmail.com"
__status__ = "Production"


from Crypto.Hash import SHA512
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

REM_SALT_LEN = 16



class BlackBox:

    def __init__(self, nm_file, b1_pwd):
        self.nm_file = nm_file
        self.b1_pwd = b1_pwd
        self.b_content = b''
        self.z_blk = b''

    def get_main_k(self):
        """ Derive a PBKDF2 key from a 'no-local keymaster' """
        salt = get_random_bytes(REM_SALT_LEN)
        keys = PBKDF2(self.b1_pwd, salt, 64, count=1000000, hmac_hash_module=SHA512)
        key1 = keys[:32]
        return key1, salt

    def get_local_key(self):
        """ Derive a local key from original plain file name """
        l_key = bytearray(self.nm_file, 'utf-8')
        if len(self.nm_file) < 16:
            l_key = bytearray(self.nm_file, 'utf-8') + get_random_bytes(16-len(self.nm_file))
        if len(self.nm_file) > 32:
            l_key = bytearray(self.nm_file[:32], 'utf-8')
        return l_key

    def do_encode(self):
        """ Encode Z-Block
            TO DO: Substitute Z-Block password with PBKDF2 originate one . """
        remote_key, remote_salt = self.get_main_k()
        local_key = self.get_local_key()
        cpr = Salsa20.new(key=self.b1_pwd)
        z_msg = cpr.nonce + cpr.encrypt(local_key)
        z_block0 = b"(C) 2022, Mariano Mancini " + len(z_msg).to_bytes(2, 'little') + z_msg + remote_salt
        z_block0 += bytearray("ORG", 'ascii')+len(self.nm_file).to_bytes(2, 'little')+bytearray(self.nm_file, 'ascii')
        t_byt = get_random_bytes(512 - len(z_block0))
        z_block0 += t_byt
        z_block1 = get_random_bytes(26)+z_block0[26:]

        try:
            with open(self.nm_file, "rb") as fi:
                self.b_content = fi.read(-1)
        except IOError:
            print("Errore apertura file")

        cpr = Salsa20.new(key=local_key)
        ctx = z_block0 + cpr.nonce + cpr.encrypt(self.b_content) + z_block1

        try:
            with open(self.nm_file + ".enx", "wb") as fo:
                fo.write(ctx)
        except IOError:
            print("Errore apertura file")

    def do_decode(self):
        """ Decode a previously encoded file """
        try:
            with open(self.nm_file, "rb") as f:
                self.b_content = f.read(-1)
            # Decode Z-Block #0 : extract local key from the Z-Block
            z_block = self.b_content[:512]
            m_origin = z_block[26] + 256 * z_block[27]
            m_nonce = z_block[28:36]

            cpr = Salsa20.new(key=self.b1_pwd, nonce=m_nonce)
            local_key = cpr.decrypt(z_block[36:36 + (m_origin - 8)])
            # remote_salt = z_block[36+(m_origin-8):36+(m_origin-8)+REM_SALT_LEN]

            # Decode the rest of file with the local key and nounce found in Z-Block
            m_nonce = self.b_content[512:520]
            ciphertext = self.b_content[520:len(self.b_content) - 512]
            cipher = Salsa20.new(key=local_key, nonce=m_nonce)
            data = cipher.decrypt(ciphertext)
            return data

        except IOError:
            print("Errore apertura file")


if __name__ == '__main__':
    # fl = BlackBox("Miofile.txt", b'my super secret0 con altra pass1')
    # fl.do_encode()
    fl = BlackBox("Fileguats.txt", b'my super secret0 con altra pass1')
    print(fl.do_decode())
