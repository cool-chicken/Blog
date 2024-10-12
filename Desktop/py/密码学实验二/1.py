import hashlib
import base64
from Crypto.Cipher import AES
import binascii

def pad(text):
    padding_len = AES.block_size - len(text) % AES.block_size
    padding = b'\x01' + b'\x00' * (padding_len - 1)
    return text + padding

def unpad(text):
    return text.rstrip(b'\x00').rstrip(b'\x01')

def unknown_number():
    number = "111116"
    weight = "731"
    total = 0
    for i in range(len(number)):
        total += int(number[i]) * int(weight[i % 3])
    return total % 10  #7

def calculate_kseed():
    MRZ_information = "12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4"  #加上7
    H_information = hashlib.sha1((MRZ_information[:10] + MRZ_information[13:20] + MRZ_information[21:28]).encode()).hexdigest() 
    K_seed = H_information[:32]  
    return K_seed

# Calculate Ka and Kb from K_seed
def calculate_ka_kb(K_seed):
    c = "00000001"
    d = K_seed + c 
    H_d = hashlib.sha1(binascii.unhexlify(d)).hexdigest()  # SHA-1 hash of K_seed+c
    ka = H_d[:16]  
    kb = H_d[16:32] 
    return ka, kb

def parity_check(hex_str):
    k_list = []
    binary_str = bin(int(hex_str, 16))[2:].zfill(64) 
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i + 7]  # First 7 bits
        parity_bit = '1' if byte.count('1') % 2 == 0 else '0' 
        k_list.append(byte + parity_bit)
    corrected_key = hex(int(''.join(k_list), 2))[2:].zfill(16)  
    return corrected_key

def decrypt_message(encrypted_text):
    K_seed = calculate_kseed()  
    ka, kb = calculate_ka_kb(K_seed)  
    k1 = parity_check(ka)  
    k2 = parity_check(kb)  

    # AES key = k1 + k2
    key = k1 + k2
    print(f"Key: {key}")

    ciphertext = base64.b64decode(encrypted_text)
    IV = '0' * 32 

    # Decrypt using AES CBC 
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, binascii.unhexlify(IV))
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded).decode('utf-8', errors='ignore')
    
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    print(unknown_number())
    encrypted_text = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
    decrypt_message(encrypted_text)
