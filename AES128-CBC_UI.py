import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as libpad, unpad as libunpad
import base64, time, tracemalloc

def benchmark():
    time_ = time.time()
    cpu = time.thread_time()
    current, mem = tracemalloc.get_traced_memory()

    return cpu, mem, time_

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def pad(plaintext):
    plaintextbytes = plaintext.encode()
    padding_len = 16 - (len(plaintextbytes) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintextbytes + padding

def unpad(padded_plaintext):
    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len]

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def add_round_key(text, key):
    return xor_bytes(text, key)

def sub_bytes(pbytes):
    for i in range(4):
        for j in range(4):
            val = pbytes[i][j][0]  
            pbytes[i][j] = bytes([s_box[val]])
    return pbytes

def inv_sub_bytes(pbytes):
    for i in range(4):
        for j in range(4):
            val = pbytes[i][j][0]
            pbytes[i][j] = bytes([inv_s_box[val]])
    return pbytes

def bytes_to_bytesmatrix(plainbytes):
    index = 0

    matrix = []
    for i in range(4):
        matrix.append([])
        for j in range (i, i+13, 4):
            matrix[i].append(bytes([plainbytes[j]]))
            index += 1
    
    return matrix

def shift_rows(bytes_matrix):
    bytes_matrix[1] = bytes_matrix[1][1:] + bytes_matrix[1][:1]
    bytes_matrix[2] = bytes_matrix[2][2:] + bytes_matrix[2][:2]
    bytes_matrix[3] = bytes_matrix[3][3:] + bytes_matrix[3][:3]
    return bytes_matrix

def inv_shift_rows(bytes_matrix):
    bytes_matrix[1] = bytes_matrix[1][-1:] + bytes_matrix[1][:-1]
    bytes_matrix[2] = bytes_matrix[2][-2:] + bytes_matrix[2][:-2]
    bytes_matrix[3] = bytes_matrix[3][-3:] + bytes_matrix[3][:-3]
    return bytes_matrix

def xtime(a):
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    else:
        return (a << 1) & 0xFF
    
def mul_by_2(x): return xtime(x)
def mul_by_3(x): return xtime(x) ^ x

def mul_by_9(x):  return xtime(xtime(xtime(x))) ^ x
def mul_by_11(x): return xtime(xtime(xtime(x)) ^ x) ^ x
def mul_by_13(x): return xtime(xtime(xtime(x) ^ x)) ^ x
def mul_by_14(x): return xtime(xtime(xtime(x) ^ x) ^ x)

def mix_single_column(col):
    a = [col[i][0] for i in range(4)]
    b = [xtime(a[i]) for i in range(4)]
    c0 = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
    c1 = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
    c2 = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
    c3 = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]
    return [bytes([c0]), bytes([c1]), bytes([c2]), bytes([c3])]

def inv_mix_single_column(col):
    a = [col[i][0] for i in range(4)]

    c0 = mul_by_14(a[0]) ^ mul_by_11(a[1]) ^ mul_by_13(a[2]) ^ mul_by_9(a[3])
    c1 = mul_by_9(a[0])  ^ mul_by_14(a[1]) ^ mul_by_11(a[2]) ^ mul_by_13(a[3])
    c2 = mul_by_13(a[0]) ^ mul_by_9(a[1])  ^ mul_by_14(a[2]) ^ mul_by_11(a[3])
    c3 = mul_by_11(a[0]) ^ mul_by_13(a[1]) ^ mul_by_9(a[2])  ^ mul_by_14(a[3])

    return [bytes([c0]), bytes([c1]), bytes([c2]), bytes([c3])]

def mix_columns(bytes_matrix):
    for c in range(4):
        col = [bytes_matrix[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            bytes_matrix[r][c] = mixed[r]
    return bytes_matrix

def inv_mix_columns(bytes_matrix):
    for c in range(4):
        col = [bytes_matrix[r][c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            bytes_matrix[r][c] = mixed[r]
    return bytes_matrix

def expand_key(key):
    key = key.encode()
    key_matrix = [bytes(key[i:i+4]) for i in range(0, len(key), 4)]

    i = 1
    while len(key_matrix) < (11) * 4:
        word = list(key_matrix[-1])

        if len(key_matrix) % 4 == 0:
            word.append(word.pop(0))

            word = [s_box[x] for x in word]

            word[0] ^= r_con[i]
            i += 1

        word = xor_bytes(word, key_matrix[-4])
        key_matrix.append(word)

    return [b''.join(key_matrix[j:j+4]) for j in range(0, len(key_matrix), 4)]

def encrypt_block(plaintext, expanded_key):

    plaintext = add_round_key(plaintext, expanded_key[0])

    for i in range(1, 10):
        plaintext_matrix = bytes_to_bytesmatrix(plaintext)
        plaintext_matrix = sub_bytes(plaintext_matrix)
        plaintext_matrix = shift_rows(plaintext_matrix)
        plaintext_matrix = mix_columns(plaintext_matrix)
        plaintext = b''.join(plaintext_matrix[row][col] for col in range(4) for row in range(4))
        plaintext = add_round_key(plaintext, expanded_key[i])
    
    plaintext_matrix = bytes_to_bytesmatrix(plaintext)

    plaintext_matrix = sub_bytes(plaintext_matrix)
    plaintext_matrix = shift_rows(plaintext_matrix)
    plaintext = b''.join(plaintext_matrix[row][col] for col in range(4) for row in range(4))
    plaintext = add_round_key(plaintext, expanded_key[-1])

    return plaintext

def decrypt_block(ciphertext, expanded_key):
    plaintext = add_round_key(ciphertext, expanded_key[-1])

    plaintext_matrix = bytes_to_bytesmatrix(plaintext)

    plaintext_matrix = inv_shift_rows(plaintext_matrix)
    plaintext_matrix = inv_sub_bytes(plaintext_matrix)
    plaintext = b''.join(plaintext_matrix[row][col] for col in range(4) for row in range(4))
    plaintext = add_round_key(plaintext, expanded_key[9])

    for i in range(8, -1, -1):
        plaintext_matrix = bytes_to_bytesmatrix(plaintext)
        plaintext_matrix = inv_mix_columns(plaintext_matrix)
        plaintext_matrix = inv_shift_rows(plaintext_matrix)
        plaintext_matrix = inv_sub_bytes(plaintext_matrix)
        plaintext = b''.join(plaintext_matrix[row][col] for col in range(4) for row in range(4))
        plaintext = add_round_key(plaintext, expanded_key[i])

    return plaintext

def custom_encrypt(plaintext: str, key: str, iv: str) -> bytes:
    expanded_key = expand_key(key)
    plaintext = pad(plaintext)

    ciphertext = b""

    previous = iv.encode()
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        ct_block = encrypt_block(xor_bytes(block, previous), expanded_key)
        ciphertext += ct_block
        previous = ct_block

    return ciphertext

def custom_decrypt(ciphertext: bytes, key: str, iv: str) -> str:
    expanded_key = expand_key(key)
    plaintext = b""
    previous = iv.encode()

    for i in range(0, len(ciphertext), 16):
        ct_block = ciphertext[i:i+16]
        decrypted_block = decrypt_block(ct_block, expanded_key)
        pt_block = xor_bytes(decrypted_block, previous)
        plaintext += pt_block
        previous = ct_block

    plaintext = unpad(plaintext)
    return plaintext.decode()

def encrypt():
    plaintext = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get().strip()
    iv = entry_iv.get().strip()

    if len(key) != 16 or len(iv) != 16:
        messagebox.showerror("Error", "Key and IV must be exactly 16 bytes.")
        return

    # Custom encryption
    tracemalloc.start()
    cpu_start, mem_start, time_start = benchmark()
    my_ciphertext = custom_encrypt(plaintext, key, iv)
    cpu_end, mem_end, time_end = benchmark()
    tracemalloc.stop()
    my_benchmark = {"time": (time_end-time_start)*1000, "cpu": cpu_end-cpu_start, "mem":(mem_end-mem_start)}
    my_ciphertext_b64 = base64.b64encode(my_ciphertext).decode()

    # Library encryption
    tracemalloc.start()
    cpu_start, mem_start, time_start = benchmark()
    lib_cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    lib_ciphertext = lib_cipher.encrypt(libpad(plaintext.encode(), AES.block_size))
    cpu_end, mem_end, time_end = benchmark()
    tracemalloc.stop()
    lib_benchmark = {"time": (time_end-time_start)*1000, "cpu": cpu_end-cpu_start, "mem":(mem_end-mem_start)}
    label_bench.config(text=f"Library[ time: {lib_benchmark["time"]:.3f}ms / cpu: {lib_benchmark["cpu"]}s / memory: {lib_benchmark["mem"]}B ]\ncustom[ time: {my_benchmark["time"]:.3f}ms / cpu: {my_benchmark["cpu"]}s / memory: {my_benchmark["mem"]}B ]")
    lib_ciphertext_b64 = base64.b64encode(lib_ciphertext).decode()

    if my_ciphertext == lib_ciphertext:
        result_text = f"Matched!\n\nCiphertext (Base64):\n{my_ciphertext_b64}"
    else:
        result_text = f"Not Matching!\n\nYour Ciphertext (Base64):\n{my_ciphertext_b64}\n\nLibrary Ciphertext (Base64):\n{lib_ciphertext_b64}"

    entry_result.config(state="normal")
    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, result_text)
    entry_result.config(state="disabled")


def decrypt():
    ciphertext_b64 = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get().strip()
    iv = entry_iv.get().strip()

    if len(key) != 16 or len(iv) != 16:
        messagebox.showerror("Error", "Key and IV must be exactly 16 bytes.")
        return

    try:
        ciphertext = base64.b64decode(ciphertext_b64)

        # Custom decryption
        tracemalloc.start()
        cpu_start, mem_start, time_start = benchmark()
        my_plaintext = custom_decrypt(ciphertext, key, iv)
        cpu_end, mem_end, time_end = benchmark()
        tracemalloc.stop()
        my_benchmark = {"time": (time_end-time_start)*1000, "cpu": cpu_end-cpu_start, "mem":(mem_end-mem_start)}

        # Library decryption
        tracemalloc.start()
        cpu_start, mem_start, time_start = benchmark()
        lib_cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        lib_plaintext = libunpad(lib_cipher.decrypt(ciphertext), AES.block_size).decode()
        cpu_end, mem_end, time_end = benchmark()
        tracemalloc.stop()
        lib_benchmark = {"time": (time_end-time_start)*1000, "cpu": cpu_end-cpu_start, "mem":(mem_end-mem_start)}
        label_bench.config(text=f"Library[ time: {lib_benchmark["time"]:.3f}ms / cpu: {lib_benchmark["cpu"]}s / memory: {lib_benchmark["mem"]}B ]\ncustom[ time: {my_benchmark["time"]:.3f}ms / cpu: {my_benchmark["cpu"]}s / memory: {my_benchmark["mem"]}B ]")

        if my_plaintext == lib_plaintext:
            result_text = f"Matched!\n\nDecrypted Text:\n{my_plaintext}"
        else:
            result_text = f"Not Matching!\n\nYour Decryption:\n{my_plaintext}\n\nLibrary Decryption:\n{lib_plaintext}"

        entry_result.config(state="normal")
        entry_result.delete("1.0", tk.END)
        entry_result.insert(tk.END, result_text)
        entry_result.config(state="disabled")

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# ---------- TKINTER GUI ----------

def toggle_mode():
    if mode.get() == "Encrypt":
        btn_action.config(text="Encrypt", command=encrypt)
        label_text.config(text="Plaintext:")
    else:
        btn_action.config(text="Decrypt", command=decrypt)
        label_text.config(text="Ciphertext (Base64):")



root = tk.Tk()
root.title("AES-128 Encryption/Decryption Checker")
root.geometry("700x550")

mode = tk.StringVar(value="Encrypt")


tk.Radiobutton(root, text="Encrypt", variable=mode, value="Encrypt", command=toggle_mode).grid(row=0, column=0)
tk.Radiobutton(root, text="Decrypt", variable=mode, value="Decrypt", command=toggle_mode).grid(row=0, column=1)


label_text = tk.Label(root, text="Plaintext:")
label_text.grid(row=1, column=0, sticky="w")
entry_text = tk.Text(root, height=8, width=80)
entry_text.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

tk.Label(root, text="Key (16 bytes):").grid(row=3, column=0, sticky="w")
entry_key = tk.Entry(root, width=35)
entry_key.grid(row=3, column=1, pady=5)

tk.Label(root, text="IV (16 bytes):").grid(row=4, column=0, sticky="w")
entry_iv = tk.Entry(root, width=35)
entry_iv.grid(row=4, column=1, pady=5)


btn_action = tk.Button(root, text="Encrypt", command=encrypt)
btn_action.grid(row=5, column=0, columnspan=2, pady=10)


tk.Label(root, text="Result:").grid(row=6, column=0, sticky="w")
label_bench = tk.Label(root, text="benchmark: ")
label_bench.grid(row=8, column=0, sticky="w")
entry_result = tk.Text(root, height=10, width=80)
entry_result.grid(row=7, column=0, columnspan=2, padx=10, pady=5)
entry_result.config(state="disabled")

root.mainloop()