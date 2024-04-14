import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from binascii import unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoTool():
    def decrypt_join_accept(self, packet, appkey):
        payload = packet[4:-2]  # remove chcksum
        cipher = AES.new(appkey, AES.MODE_ECB)
        return cipher.encrypt(payload)

    def encrypt_join_accept(self, packet, appkey):
        payload = packet[4:]
        cipher = AES.new(appkey, AES.MODE_ECB)
        return cipher.decrypt(payload)

    def __hex_to_bytes(hex_string):
        return binascii.unhexlify(hex_string)

    def __aes_encrypt(self, app_key, control_byte, app_nonce, net_id, dev_nonce):
        key_bytes = self.hex_to_bytes(app_key)
        control_byte_bytes = bytes([control_byte])
        app_nonce_bytes = self.hex_to_bytes(app_nonce)
        net_id_bytes = self.hex_to_bytes(net_id)
        dev_nonce_bytes = self.hex_to_bytes(dev_nonce)

        data = control_byte_bytes + app_nonce_bytes + net_id_bytes + dev_nonce_bytes
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted = cipher.encrypt(data)

        return binascii.hexlify(encrypted).decode()



    def derive_session_keys(self, app_key, nwk_key, join_eui, app_nonce, net_id, dev_nonce):
        """AppNonce is equivalent to the JoinNonce. In case of LoRaWANv1.0, the app_key and nwk_key are the same, as well as AppEUI and JoinEUI"""
        nwk_skey = self.aes_encrypt(app_key, 0x01, app_nonce, net_id, dev_nonce)
        app_skey = self.aes_encrypt(app_key, 0x02, app_nonce, net_id, dev_nonce)

        FNwkSIntKey = self.aes_encrypt(nwk_key, 0x01, app_nonce, join_eui, dev_nonce)
        SNwkSIntKey = self.aes_encrypt(nwk_key, 0x03, app_nonce, join_eui, dev_nonce)
        NwkSEncKey = self.aes_encrypt(nwk_key, 0x04, app_nonce, join_eui, dev_nonce)

        return nwk_skey, app_skey, FNwkSIntKey, SNwkSIntKey, NwkSEncKey

    def __to_bytes(self, s):
        if sys.version_info < (3,):
            return "".join(map(chr, s))
        else:
            return bytes(s)

    def FRMPayload_decrypt(self, payload_hex, sequence_counter, key, dev_addr, direction=0):
        """
        Source: https://github.com/jieter/python-lora/blob/master/lora/crypto.py#L54

        LoraMac decrypt

        Which is actually encrypting a predefined 16-byte block (ref LoraWAN
        specification 4.3.3.1) and XORing that with each block of data.

        payload_hex: hex-encoded payload (FRMPayload)
        sequence_counter: integer, sequence counter (FCntUp)
        key: 16-byte hex-encoded AES key. (i.e. AABBCCDDEEFFAABBCCDDEEFFAABBCCDD)
        dev_addr: 4-byte hex-encoded DevAddr (i.e. AABBCCDD)
        direction: 0 for uplink packets, 1 for downlink packets

        returns an array of byte values.

        This method is based on `void LoRaMacPayloadEncrypt()` in
        https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/LoRaMacCrypto.c#L108
        """
        key = unhexlify(key)
        dev_addr = unhexlify(dev_addr)
        buffer = bytearray(unhexlify(payload_hex))
        size = len(buffer)

        bufferIndex = 0
        # block counter
        ctr = 1

        # output buffer, initialize to input buffer size.
        encBuffer = [0x00] * size

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

        def aes_encrypt_block(aBlock):
            """
            AES encrypt a block.
            aes.encrypt expects a string, so we convert the input to string and
            the return value to bytes again.
            """
            encryptor = cipher.encryptor()

            return bytearray(encryptor.update(self.__to_bytes(aBlock)) + encryptor.finalize())

        # For the exact definition of this block refer to
        # 'chapter 4.3.3.1 Encryption in LoRaWAN' in the LoRaWAN specification
        aBlock = bytearray(
            [
                0x01,  # 0 always 0x01
                0x00,  # 1 always 0x00
                0x00,  # 2 always 0x00
                0x00,  # 3 always 0x00
                0x00,  # 4 always 0x00
                direction,  # 5 dir, 0 for uplink, 1 for downlink
                dev_addr[3],  # 6 devaddr, lsb
                dev_addr[2],  # 7 devaddr
                dev_addr[1],  # 8 devaddr
                dev_addr[0],  # 9 devaddr, msb
                sequence_counter & 0xFF,  # 10 sequence counter (FCntUp) lsb
                (sequence_counter >> 8) & 0xFF,  # 11 sequence counter
                (sequence_counter >> 16) & 0xFF,  # 12 sequence counter
                (sequence_counter >> 24) & 0xFF,  # 13 sequence counter (FCntUp) msb
                0x00,  # 14 always 0x01
                0x00,  # 15 block counter
            ]
        )

        # complete blocks
        while size >= 16:
            aBlock[15] = ctr & 0xFF
            ctr += 1
            sBlock = aes_encrypt_block(aBlock)
            for i in range(16):
                encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i]

            size -= 16
            bufferIndex += 16

        # partial blocks
        if size > 0:
            aBlock[15] = ctr & 0xFF
            sBlock = aes_encrypt_block(aBlock)
            for i in range(size):
                encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i]

        return encBuffer


if __name__ == "__main__":
    c = CryptoTool()
    pt = c.FRMPayload_decrypt('247D22681F66D35B67AD93B3FE', 0x22, 'C1076C63B971710A708E3471A7C803D7', '260b4ede', 0)
    print(pt)
    print(bytes(pt).hex())
    print(bytes(pt).decode('iso-8859-1'))
