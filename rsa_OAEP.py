from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

PASSPHRASE = "lab04uvg"


def cifrar_con_rsa(mensaje: bytes, public_key_pem: bytes) -> bytes:
    """
    Cifra un mensaje usando RSA-OAEP con la clave pública proporcionada.
    
    Args:
        mensaje (bytes): El mensaje a cifrar.
        public_key_pem (bytes): La clave pública en formato PEM.
    
    Returns:
        bytes: El mensaje cifrado.
    """
    # Importar la clave pública
    public_key = RSA.import_key(public_key_pem)
    
    # Crear el cifrador OAEP con SHA-256
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    
    # Cifrar el mensaje
    ciphertext = cipher.encrypt(mensaje)
    
    return ciphertext


def descifrar_con_rsa(cifrado: bytes, private_key_pem: bytes) -> bytes:
    """
    Descifra un mensaje usando RSA-OAEP con la clave privada proporcionada.
    
    Args:
        cifrado (bytes): El mensaje cifrado.
        private_key_pem (bytes): La clave privada en formato PEM.
    
    Returns:
        bytes: El mensaje descifrado.
    """
    # Importar la clave privada (protegida con passphrase)
    private_key = RSA.import_key(private_key_pem, passphrase=PASSPHRASE)
    
    # Crear el descifrador OAEP con SHA-256
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    
    # Descifrar el mensaje
    plaintext = cipher.decrypt(cifrado)
    
    return plaintext


if __name__ == '__main__':
    # Cargar claves generadas en el ejercicio anterior
    with open("public_key.pem", "rb") as f:
        pub = f.read()
    with open("private_key.pem", "rb") as f:
        priv = f.read()

    mensaje_original = b"El mensaje sera la clave secreta de AES"
    cifrado = cifrar_con_rsa(mensaje_original, pub)
    descifrado = descifrar_con_rsa(cifrado, priv)

    print(f"Original  : {mensaje_original}")
    print(f"Cifrado   : {cifrado.hex()[:64]}...")  # primeros 64 chars hex
    print(f"Descifrado: {descifrado}")

    # Pregunta: ¿Por qué cifrar el mismo mensaje dos veces produce
    # resultados distintos? Demuéstralo y explica qué propiedad de OAEP lo causa.
    print("\n--- Demostración de propiedad OAEP ---")
    c1 = cifrar_con_rsa(mensaje_original, pub)
    c2 = cifrar_con_rsa(mensaje_original, pub)
    print(f"Cifrado 1: {c1.hex()[:64]}...")
    print(f"Cifrado 2: {c2.hex()[:64]}...")
    print(f"c1 == c2: {c1 == c2}")  # Esperado: False
