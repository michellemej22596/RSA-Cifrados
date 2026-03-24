import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from generar_claves import generar_par_claves

PASSPHRASE = "lab04uvg"

# Constantes para el formato del paquete cifrado
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12    # 96 bits (estándar para GCM)
TAG_SIZE = 16      # 128 bits


def encrypt_document(document: bytes, recipient_public_key_pem: bytes) -> bytes:
    """
    Cifra un documento usando cifrado híbrido RSA-OAEP + AES-256-GCM.

    El proceso es:
    1. Generar una clave AES aleatoria de 256 bits
    2. Cifrar el documento con AES-GCM (genera nonce, tag y ciphertext)
    3. Cifrar la clave AES con la clave pública RSA usando OAEP

    Args:
        document (bytes): El documento a cifrar.
        recipient_public_key_pem (bytes): La clave pública RSA del destinatario en formato PEM.

    Returns:
        bytes: El paquete cifrado con el formato:
               [RSA_encrypted_key_length (2 bytes)] + [RSA_encrypted_key] + [nonce] + [tag] + [ciphertext]
    """
    # 1. Generar clave AES aleatoria de 256 bits
    aes_key = os.urandom(AES_KEY_SIZE)

    # 2. Cifrar el documento con AES-256-GCM
    nonce = os.urandom(NONCE_SIZE)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)

    # 3. Cifrar la clave AES con la clave pública RSA usando OAEP
    public_key = RSA.import_key(recipient_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # 4. Construir el paquete: [longitud clave RSA (2 bytes)] + [clave RSA cifrada] + [nonce] + [tag] + [ciphertext]
    encrypted_key_length = len(encrypted_aes_key).to_bytes(2, 'big')

    package = encrypted_key_length + encrypted_aes_key + nonce + tag + ciphertext

    return package


def decrypt_document(pkg: bytes, recipient_private_key_pem: bytes) -> bytes:
    """
    Descifra un documento cifrado con cifrado híbrido RSA-OAEP + AES-256-GCM.

    El proceso es:
    1. Extraer la clave AES cifrada del paquete
    2. Descifrar la clave AES con la clave privada RSA
    3. Descifrar el documento con AES-GCM usando la clave recuperada

    Args:
        pkg (bytes): El paquete cifrado.
        recipient_private_key_pem (bytes): La clave privada RSA del destinatario en formato PEM.

    Returns:
        bytes: El documento original descifrado.
    """
    # 1. Extraer las partes del paquete
    encrypted_key_length = int.from_bytes(pkg[:2], 'big')
    encrypted_aes_key = pkg[2:2 + encrypted_key_length]

    offset = 2 + encrypted_key_length
    nonce = pkg[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    tag = pkg[offset:offset + TAG_SIZE]
    offset += TAG_SIZE
    ciphertext = pkg[offset:]

    # 2. Descifrar la clave AES con la clave privada RSA
    private_key = RSA.import_key(recipient_private_key_pem, passphrase=PASSPHRASE)
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # 3. Descifrar el documento con AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext


if __name__ == '__main__':
    # Generar claves de 2048 bits para este ejercicio
    generar_par_claves(2048)

    with open("public_key.pem", "rb") as f:
        pub = f.read()
    with open("private_key.pem", "rb") as f:
        priv = f.read()

    # Generen un cifrado de un texto
    doc = b"Contrato de confidencialidad No. 2025-GT-001"
    print(f"Documento original: {doc}")

    pkg = encrypt_document(doc, pub)
    print(f"Paquete cifrado (primeros 64 hex): {pkg.hex()[:64]}...")
    print(f"Tamaño del paquete: {len(pkg)} bytes")

    resultado = decrypt_document(pkg, priv)
    print(f"Documento descifrado: {resultado}")
    print(f"¿Coincide?: {resultado == doc}")

    print("\n--- Prueba con archivo grande ---")
    # Prueba con archivo de 1 MB (simula un contrato real)
    doc_grande = os.urandom(1024 * 1024)
    pkg2 = encrypt_document(doc_grande, pub)
    resultado_grande = decrypt_document(pkg2, priv)
    assert resultado_grande == doc_grande
    print("Archivo 1 MB: OK")
    print(f"Tamaño original: {len(doc_grande)} bytes")
    print(f"Tamaño cifrado: {len(pkg2)} bytes")
