from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from blake3 import blake3
import struct
import os
import brotli


def compute_hash(value: str, key: str) -> bytes:
    return blake3(value.encode()).update(key.encode()).digest()


def split_chunks(
    array: bytes, chunk_size: int = 32, pad_zeroes: bool = True
) -> list[bytes]:
    chunks: list[bytes] = []

    for i in range(0, len(array), chunk_size):
        chunk = array[i : i + chunk_size]

        # pad the last block if it's shorter than 32 bytes
        if (len(chunk) < chunk_size) and pad_zeroes:
            chunk = chunk.ljust(chunk_size, b"\x00")

        chunks.append(chunk)

    return chunks


def encrypt(data: bytes, key: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


def prepare(data: Union[list[int], str]) -> bytes:
    match data:
        case list(items):
            return struct.pack(f">{len(items)}Q", *items)
        case str(data_str):
            data_bytes = data_str.encode("utf-8")
            # defaults to quality 11 (max)
            return brotli.compress(data_bytes)
        case _:
            raise NotImplementedError(f"{type(data)} not implemented for encryption.")


def unpack_list(data: bytes) -> list[int]:
    # Determine how many 8-byte integers were originally packed
    if len(data) % 8 != 0:
        raise ValueError(
            "Decrypted data length is not a multiple of 8 bytes after depadding"
        )

    count = len(data) // 8

    values = struct.unpack(f">{count}Q", data)
    return list(values)


def unpack_json(data: bytes) -> str:
    return brotli.decompress(data).decode("utf-8")


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short (missing IV)")
    # Extract IV and actual encrypted payload
    iv = ciphertext[:16]

    # Remove the zero padding that was added to make the last chunk 32 bytes
    encrypted_data = ciphertext[16:].rstrip(b"\x00")

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    return plaintext

    # # Determine how many 8-byte integers were originally packed
    # if len(plaintext) % 8 != 0:
    #     raise ValueError(
    #         "Decrypted data length is not a multiple of 8 bytes after depadding"
    #     )

    # count = len(plaintext) // 8

    # values = struct.unpack(f">{count}Q", plaintext)
    # return list(values)
