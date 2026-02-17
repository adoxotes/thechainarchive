import json
from chainarchive.encryption import (
    compute_hash,
    split_chunks,
    prepare,
    encrypt,
    decrypt,
    unpack_list,
    unpack_json,
)
import struct
import brotli
import pytest
import os


def test_compute_hash_consistency():
    val, key = "hello", "secret"
    hash1 = compute_hash(val, key)
    hash2 = compute_hash(val, key)
    assert hash1 == hash2
    assert isinstance(hash1, bytes)


@pytest.mark.parametrize(
    "input_bytes, chunk_size, pad, expected_len, last_chunk_val",
    [
        (b"12345678", 4, True, 2, b"5678"),  # Perfect fit
        (b"12345", 4, True, 2, b"5\x00\x00\x00"),  # Padding enabled
        (b"12345", 4, False, 2, b"5"),  # Padding disabled
    ],
)
def test_split_chunks(input_bytes, chunk_size, pad, expected_len, last_chunk_val):
    result = split_chunks(input_bytes, chunk_size=chunk_size, pad_zeroes=pad)
    assert len(result) == expected_len
    assert result[-1] == last_chunk_val


def test_prepare_list():
    data = [1, 2, 3]
    result = prepare(data)
    # 3 items * 8 bytes (Q) = 24 bytes
    assert len(result) == 24
    assert struct.unpack(">3Q", result) == (1, 2, 3)


def test_prepare_str():
    data = "hello world"
    result = prepare(data)
    # Should be compressed with brotli
    assert brotli.decompress(result) == b"hello world"


def test_prepare_invalid_type():
    with pytest.raises(NotImplementedError, match="not implemented"):
        prepare(123.45)  # type: ignore


def test_decrypt_too_short():
    with pytest.raises(ValueError, match="Ciphertext too short"):
        decrypt(b"short", b"any_key_16bytes_")


def test_encrypt_decrypt_roundtrip():
    # Setup
    original_list = [100, 200, 300]
    key_hex = os.urandom(16).hex()
    key_bytes = bytes.fromhex(key_hex)

    prepared_data = prepare(original_list)
    ciphertext = encrypt(prepared_data, key_hex)
    assert len(ciphertext) > 16  # IV (16) + data

    decrypted_list = unpack_list(decrypt(ciphertext, key_bytes))
    assert decrypted_list == original_list


def test_encrypt_decrypt_json_roundtrip():
    original_data = {
        "user_id": 12345,
        "urls": ["www.link1.com", "www.link2.com"],
        "metadata": {"something": "else"},
    }
    json_str = json.dumps(original_data)

    key_hex = os.urandom(16).hex()
    key_bytes = bytes.fromhex(key_hex)

    prepared_data = prepare(json_str)
    ciphertext = encrypt(prepared_data, key_hex)

    decrypted_raw_str = decrypt(ciphertext, key_bytes)
    final_data = json.loads(unpack_json(decrypted_raw_str))

    assert final_data == original_data
