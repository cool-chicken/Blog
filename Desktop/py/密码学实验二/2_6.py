from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES

UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = Random.new().read(16)

def pad(your_string, msg):
 
    paddedMsg = your_string + msg

    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg

    padding = size - (length % size)
    padValue = bytes([padding])
    paddedMsg += padValue * padding

    return paddedMsg

def detect_prefix_length():

    block_size = detect_block_size()
    test_case_1 = encryption_oracle(b'a')
    test_case_2 = encryption_oracle(b'b')

    length1 = len(test_case_1)
    length2 = len(test_case_2)

    blocks = 0
    min_length = min(length1, length2)
    for i in range(0, min_length, block_size):
        if test_case_1[i:i+block_size] != test_case_2[i:i+block_size]:
            break
        blocks += 1 
    test_input = b''
    length = blocks * block_size
    for extra in range(block_size):
        test_input += b'?'
        curr = encryption_oracle(test_input)[length: length+block_size]
        next = encryption_oracle(test_input + b'?')[length: length+block_size]
        if curr == next:
            break

    residue = block_size - len(test_input)
    length += residue
    return length


def encryption_oracle(your_string):
    plaintext = b64decode(UNKNOWN_STRING)
    paddedPlaintext = pad(your_string, plaintext)
    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedPlaintext)

    return ciphertext


def detect_block_size():
    
    feed = b"A"
    length = 0
    while True:
        cipher = encryption_oracle(feed)
        feed += feed

        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)


def detect_mode(cipher):
    
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i+chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"
    return "not ECB"

def ecb_decrypt(block_size):
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'),ord('Z'))) + [ord(' ')] + list(range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)

    plaintext = b'' 
    check_length = block_size

    prefix_len = detect_prefix_length()
    print(f"Calculated Length of Prefix = { prefix_len }")
    check_begin = (prefix_len // block_size) * block_size
    residue = prefix_len % block_size

    while True:
        prepend = b'A' * (block_size - 1 -
                          ((len(plaintext)+residue) % block_size))
        actual = encryption_oracle(
            prepend)[check_begin: check_begin+check_length]

        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = prepend + plaintext + value
            produced = encryption_oracle(your_string)[
                check_begin: check_begin+check_length]
            if actual == produced:
                plaintext += value
                found = True
                break

        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: \n{ plaintext.decode('ascii') }")
            return

        if (len(plaintext) + residue) % block_size == 0:
            check_length += block_size


def main():
    block_size = detect_block_size()
    print(f"Block Size is { block_size }")
    repeated_plaintext = b"A" * 50
    cipher = encryption_oracle(repeated_plaintext)
    mode = detect_mode(cipher)
    print(f"Mode of encryption is { mode }")
    ecb_decrypt(block_size)


if __name__ == "__main__":
    main()
