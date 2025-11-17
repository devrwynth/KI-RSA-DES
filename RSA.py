# Function to perform modular exponentiation
def power(base, expo, m):
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo = expo // 2
    return res

# Function to find modular inverse of e under modulo phi
def modInverse(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    return -1

# RSA Key Generation
def generateKeys():
    p = 7919
    q = 1009
    
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e, where 1 < e < phi(n) and gcd(e, phi(n)) == 1
    e = 0
    for e in range(2, phi):
        if gcd(e, phi) == 1:
            break

    # Compute d such that e * d ≡ 1 (mod phi(n))
    d = modInverse(e, phi)

    return e, d, n

# Function to calculate gcd
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Encrypt message using public key (e, n)
def encrypt(m, e, n):
    return power(m, e, n)

# Decrypt message using private key (d, n)
def decrypt(c, d, n):
    return power(c, d, n)

# --- Fungsi Utilitas Baru (Tambahkan di bagian RSA) ---
def hex_to_int(hex_str):
    """Mengubah string hex (kunci DES) menjadi integer untuk RSA."""
    return int(hex_str, 16)

def int_to_hex(num):
    """Mengubah integer hasil dekripsi RSA menjadi string hex."""
    # Menghilangkan prefiks '0x' dan memastikan huruf kapital
    return hex(num).replace('0x', '').upper()
# --------------------------------------------------------

def main():
    # ============================================
    # 1. PERSIAPAN: GENERATE KUNCI RSA & DES KEY
    # ============================================
    
    # --- A. Generate Kunci RSA ---
    e, d, n = generateKeys()
    print("="*45)
    print("=== HYBRID SYSTEM: RSA + DES ===")
    print("="*45)
    print(f"RSA Kunci Publik (e, n): ({e}, {n})")
    print(f"RSA Kunci Privat (d, n): ({d}, {n})")
    print("-"*45)
    
    # --- B. Input dan Proses Kunci DES ---
    key_text = input("Masukkan kunci DES rahasia (disarankan 8 karakter): ")
    
    # Kunci DES di-padding/truncation (seperti di kode asli)
    key_bytes = key_text.encode('utf-8')
    if len(key_bytes) != 8:
        print(f"Key di-adjust ke 8 byte: {len(key_bytes)} byte.")
        key_bytes = key_bytes.ljust(8, b'\x00')[:8]
        
    original_key_hex = key_bytes.hex().upper()
    
    # Generate Kunci Ronde DES
    rkb_enc = generate_keys(original_key_hex)
    rkb_dec = rkb_enc[::-1]

    # --- C. Input Plaintext DES ---
    plaintext = input("Masukkan plaintext untuk dienkripsi oleh DES: ")
    print("-"*45)

    # ============================================
    # 2. PROSES ENKRIPSI (Pengirim)
    # ============================================
    print(">>> 📤 PROSES ENKRIPSI (Sisi Pengirim) <<<")
    
    # 2a. ENKRIPSI KUNCI DES MENGGUNAKAN RSA
    # Konversi hex key DES ke integer
    key_int_rsa = hex_to_int(original_key_hex)
    
    # Enkripsi kunci DES menggunakan KUNCI PUBLIK RSA (e, n)
    cipher_key_rsa = encrypt(key_int_rsa, e, n)
    print(f"Kunci DES (Hex): {original_key_hex}")
    print(f"Kunci DES Terenkripsi oleh RSA (C_key): {cipher_key_rsa}")
    
    # 2b. ENKRIPSI PESAN MENGGUNAKAN DES
    # Pesan dienkripsi dengan kunci DES yang asli
    cipher_message_des = des_encrypt_dynamic(plaintext, rkb_enc)
    print(f"Pesan Asli Terenkripsi oleh DES (C_msg): {cipher_message_des[:30]}...")
    
    print("-"*45)

    # ============================================
    # 3. PROSES DEKRIPSI (Penerima)
    # ============================================
    print(">>> 📥 PROSES DEKRIPSI (Sisi Penerima) <<<")
    
    # 3a. DEKRIPSI KUNCI DES MENGGUNAKAN RSA
    # Menggunakan KUNCI PRIVAT RSA (d, n) untuk mendapatkan kembali kunci DES
    decrypted_key_int = decrypt(cipher_key_rsa, d, n)
    recovered_key_hex = int_to_hex(decrypted_key_int)
    
    # Generate ulang RKB dari kunci DES yang dipulihkan
    rkb_final_dec = generate_keys(recovered_key_hex)[::-1]
    
    print(f"Kunci DES Terdekripsi oleh RSA (M_key): {recovered_key_hex}")
    
    # 3b. DEKRIPSI PESAN MENGGUNAKAN KUNCI DES YANG DIPULIHKAN
    plain_out = des_decrypt_dynamic(cipher_message_des, rkb_final_dec)
    
    print(f"Pesan Terdekripsi oleh DES (Plaintext): {plain_out}")
    
    print("="*45)
    # --- VERIFIKASI AKHIR ---
    print(f"Verifikasi Kunci: {'Berhasil!' if original_key_hex == recovered_key_hex else 'Gagal!'}")
    print(f"Verifikasi Pesan: {'Berhasil!' if plaintext == plain_out else 'Gagal!'}")

if _name_ == "_main_":
    main()