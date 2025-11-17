import math
# Menggunakan UTF-8 untuk mendukung karakter yang lebih luas

# ===============================================
# === UTILITY FUNCTIONS (Modified for Robustness) ===
# ===============================================

# Text to Hex (Menggunakan encode('utf-8') untuk karakter non-Latin)
def text_to_hex(text):
    """Mengubah teks menjadi representasi hex (string), menggunakan UTF-8."""
    return text.encode('utf-8').hex().upper()

# Hex to Text (Digunakan setelah menghapus padding)
def hex_to_text(hex_str):
    """Mengubah string hex kembali menjadi teks, menggunakan UTF-8."""
    # Pastikan panjang hex genap, jika tidak, tambahkan '0' di awal
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
        
    data_bytes = bytes.fromhex(hex_str)
    
    # Coba decode dengan UTF-8
    try:
        return data_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # Fallback jika ada masalah decoding (jarang terjadi setelah unpadding)
        return data_bytes.decode('latin-1', errors='ignore')

# Hex to Binary
def hex2bin(s):
    """Mengubah string Hex (misal: 'A5') menjadi string Biner (misal: '10100101')."""
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    binary_str = ""
    for char in s:
        binary_str += mp[char.upper()]
    return binary_str

# Binary to Hex
def bin2hex(s):
    """Mengubah string Biner (misal: '10100101') menjadi string Hex (misal: 'A5')."""
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    hex_str = ""
    # Pastikan panjang biner kelipatan 4
    while len(s) % 4 != 0:
        s = '0' + s # Tambahkan '0' di depan jika tidak pas
        
    for i in range(0, len(s), 4):
        chunk = s[i:i + 4]
        hex_str += mp[chunk]
    return hex_str

# Binary to Decimal (Disederhanakan untuk input string biner)
def bin2dec(binary_str):
    """Mengubah string biner menjadi bilangan desimal."""
    return int(binary_str, 2)

# Decimal to Binary (Memastikan output 4 bit)
def dec2bin(num):
    """Mengubah desimal menjadi biner dan memastikan panjangnya 4 bit (padding)."""
    return format(num, '04b')

# Permutasi bit sesuai tabel
def permute(k, arr, n):
    """Melakukan permutasi bit berdasarkan tabel yang diberikan."""
    permutation = ""
    for i in range(0, n):
        permutation += k[arr[i] - 1]
    return permutation

# Geser bit ke kiri sejumlah tertentu
def shift_left(k, nth_shifts):
    """Melakukan cyclic left shift pada string biner."""
    return k[nth_shifts:] + k[:nth_shifts]

# Operasi XOR antara dua string biner
def xor(a, b):
    """Melakukan operasi XOR bitwise antara dua string biner."""
    ans = ""
    for i in range(len(a)):
        ans += "0" if a[i] == b[i] else "1"
    return ans

# ===============================================
# === DES ALGORITHM CORE (Modified to process_block) ===
# ===============================================

# Fungsi untuk menghasilkan 16 kunci ronde dari kunci utama
def generate_keys(key_hex):
    """Menghasilkan 16 sub-kunci (48-bit) untuk 16 ronde DES."""
    key = hex2bin(key_hex)
    # Parity bit drop table (PC-1, 64-bit key -> 56-bit key)
    keyp = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    # Number of bit shifts per round
    shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    # Key- Compression Table (PC-2, 56-bit -> 48-bit subkey)
    key_comp = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    
    # Initial Permutation PC-1
    key = permute(key, keyp, 56)
    left = key[:28]
    right = key[28:]
    rkb = [] # Round Key Biner
    
    for i in range(16):
        # Geser C dan D
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        
        # Gabungkan C dan D, lalu kompresi (PC-2) untuk mendapatkan kunci ronde
        combine = left + right
        round_key = permute(combine, key_comp, 48)
        rkb.append(round_key)
        
    return rkb

# Fungsi pemrosesan inti DES untuk SATU blok 64-bit
def process_block(block_hex, rkb):
    """
    Melakukan proses DES untuk satu blok (64-bit) (Enkripsi atau Dekripsi).
    rkb harus urutan kunci normal untuk enkripsi, dan terbalik untuk dekripsi.
    """
    # [Tabel DES lainnya di sini, dihilangkan untuk keringkasan]
    
    # Initial Permutation Table
    initial_perm = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    # Expansion D-box Table
    exp_d = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    # Straight Permutation Table
    per = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    # 8 S-boxes
    sbox = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]
    # Final Permutation Table
    final_perm = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    pt = hex2bin(block_hex)                      # Ubah blok hex ke biner (64 bit)
    pt = permute(pt, initial_perm, 64)           # Terapkan Initial Permutation
    left = pt[:32]
    right = pt[32:]
    
    # 16 Ronde DES
    for i in range(16):
        R_before = right
        right_expanded = permute(right, exp_d, 48)  # Expansion (32 bit -> 48 bit)
        xor_x = xor(right_expanded, rkb[i])          # XOR dengan Kunci Ronde (48 bit)
        
        sbox_str = ""
        for j in range(8):
            # Tentukan baris (bit 1 dan 6) dan kolom (bit 2-5)
            row = int(xor_x[j*6] + xor_x[j*6+5], 2)
            col = int(xor_x[j*6+1:j*6+5], 2)
            val = sbox[j][row][col]                 # Ambil nilai S-box (4 bit)
            sbox_str += dec2bin(val)
            
        sbox_str = permute(sbox_str, per, 32)       # P-box permutation (32 bit)
        R_new = xor(left, sbox_str)                 # R_i = L_{i-1} XOR f(R_{i-1}, K_i)
        left = R_before                             # L_i = R_{i-1}
        right = R_new                               # R_i baru

        # Tukar blok L dan R (hanya untuk i=0 hingga i=14)
        if i != 15:
            left, right = right, left
            
    combine = right + left                       # Gabungkan R16 + L16 (Tanpa Pertukaran Akhir)
    cipher_bin = permute(combine, final_perm, 64)  # Terapkan Final Permutation
    return bin2hex(cipher_bin)

# ===============================================
# === DYNAMIC BLOCK PROCESSING WITH PADDING ===
# ===============================================

# Fungsi untuk Menambahkan Padding (PKCS#7)
# Ukuran blok DES adalah 8 byte (64 bit).
def add_padding(text, block_size=8):
    """Menambahkan PKCS#7 padding agar panjang data kelipatan 8 byte."""
    data_bytes = text.encode('utf-8')
    padding_len = block_size - (len(data_bytes) % block_size)
    # Nilai setiap byte padding sama dengan panjang padding (e.g., 0x03, 0x03, 0x03)
    padding = bytes([padding_len]) * padding_len
    return data_bytes + padding

# Fungsi untuk Menghapus Padding (PKCS#7)
def remove_padding(data_bytes):
    """Menghapus PKCS#7 padding dari data byte terdekripsi."""
    if not data_bytes:
        return b''
        
    padding_len = data_bytes[-1]
    # Validasi dasar padding
    if padding_len == 0 or padding_len > len(data_bytes):
         # Kasus error: padding tidak valid, kembalikan data asli (berisiko)
        return data_bytes
        
    # Cek apakah semua byte padding sesuai dengan panjangnya
    if all(data_bytes[i] == padding_len for i in range(len(data_bytes) - padding_len, len(data_bytes))):
        return data_bytes[:-padding_len]
    else:
        # Kasus error: byte padding tidak konsisten
        return data_bytes

# Fungsi untuk mengimplementasikan Enkripsi DES Dinamis (Mode ECB)
def des_encrypt_dynamic(plaintext, rkb):
    """Enkripsi plaintext panjang berapapun menggunakan DES dalam mode ECB dengan PKCS#7 padding."""
    # 1. Tambahkan Padding
    padded_bytes = add_padding(plaintext)
    
    # 2. Proses per blok (Mode ECB)
    ciphertext_hex = ""
    block_size = 8 # 8 byte per blok (16 karakter hex)
    
    for i in range(0, len(padded_bytes), block_size):
        block_bytes = padded_bytes[i:i+block_size]
        
        # Konversi blok byte ke hex (16 karakter)
        block_hex = block_bytes.hex().upper()
        
        # Enkripsi satu blok (64-bit)
        cipher_block_hex = process_block(block_hex, rkb)
        
        # Gabungkan hasil
        ciphertext_hex += cipher_block_hex
        
    return ciphertext_hex

# Fungsi untuk mengimplementasikan Dekripsi DES Dinamis (Mode ECB)
def des_decrypt_dynamic(ciphertext_hex, rkb_rev):
    """Dekripsi ciphertext hex menggunakan DES dalam mode ECB dengan PKCS#7 unpadding."""
    # 1. Proses per blok (Mode ECB)
    decrypted_hex = ""
    block_size = 16 # 16 karakter hex (8 byte) per blok
    
    for i in range(0, len(ciphertext_hex), block_size):
        block_hex = ciphertext_hex[i:i+block_size]
        
        # Dekripsi satu blok (64-bit)
        plain_block_hex = process_block(block_hex, rkb_rev)
        
        # Gabungkan hasil
        decrypted_hex += plain_block_hex
        
    # 2. Hapus Padding
    decrypted_bytes = bytes.fromhex(decrypted_hex)
    unpadded_bytes = remove_padding(decrypted_bytes)
    
    # 3. Konversi byte ke string teks
    return unpadded_bytes.decode('utf-8', errors='ignore') # Gunakan 'ignore' untuk menghindari error tak terduga

def generate_rkb(key_text):
    # --- Input Key ---
            
    # Key harus 8 byte (64 bit). Melakukan Padding/Truncation jika perlu.
    key_bytes = key_text.encode('utf-8')
    if len(key_bytes) < 8:
        print(f"Key terlalu pendek ({len(key_bytes)} byte). Ditambahkan null padding.")
        key_bytes = key_bytes.ljust(8, b'\x00') # Padding dengan byte null
    elif len(key_bytes) > 8:
        print(f"Key terlalu panjang ({len(key_bytes)} byte). Dipotong menjadi 8 byte.")
        key_bytes = key_bytes[:8] # Truncate
                    
    key_hex = key_bytes.hex().upper()
                    
    # Generate Kunci Ronde
    rkb = generate_keys(key_hex)
    return rkb


# ===============================================
# === MAIN EXECUTION ===
# ===============================================

def main():
    # --- Input Key ---
    key_text = input("Masukkan key (disarankan 8 karakter): ")
    
    # Key harus 8 byte (64 bit). Melakukan Padding/Truncation jika perlu.
    key_bytes = key_text.encode('utf-8')
    if len(key_bytes) < 8:
        print(f"Key terlalu pendek ({len(key_bytes)} byte). Ditambahkan null padding.")
        key_bytes = key_bytes.ljust(8, b'\x00') # Padding dengan byte null
    elif len(key_bytes) > 8:
        print(f"Key terlalu panjang ({len(key_bytes)} byte). Dipotong menjadi 8 byte.")
        key_bytes = key_bytes[:8] # Truncate
        
    key_hex = key_bytes.hex().upper()
        
    # Generate Kunci Ronde
    rkb = generate_keys(key_hex)
    rkb_rev = rkb[::-1] # Kunci terbalik untuk dekripsi

    # --- Input Plaintext ---
    plaintext = input("Masukkan plaintext (panjang berapapun): ")
    
    # --- ENKRIPSI ---
    
    cipher_hex = des_encrypt_dynamic(plaintext, rkb)
    
    print("\n" + "="*25)
    print("=== HASIL ENKRIPSI ===")
    print("="*25)
    print(f"Plaintext Asli: {plaintext}")
    print(f"Key Hex (56 bit): {key_hex}")
    print(f"Ciphertext (hex): {cipher_hex}")
    
    # --- DEKRIPSI ---
    
    plain_out = des_decrypt_dynamic(cipher_hex, rkb_rev)

    print("\n" + "="*25)
    print("=== HASIL DEKRIPSI ===")
    print("="*25)
    print(f"Ciphertext (hex): {cipher_hex}")
    print(f"Plaintext Hasil: {plain_out}")
    print(f"Verifikasi: {'Berhasil!' if plaintext == plain_out else 'Gagal!'}")

if __name__ == "__main__":
    main()