from Crypto.PublicKey import RSA

PASSPHRASE = "lab04uvg"


def generar_par_claves(bits: int = 3072):
    """
    Genera un par de claves RSA y las guarda en archivos PEM.

    Args:
        bits (int): tamaño de la clave RSA en bits.
                    Mínimo recomendado 2048, preferido 3072.
    """

    print(f"Generando claves RSA de {bits} bits...")

    # 1. Generar par de claves RSA
    key = RSA.generate(bits)

    # 2. Exportar clave privada protegida con passphrase
    private_key = key.export_key(
        format="PEM",
        passphrase=PASSPHRASE,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )

    # 3. Exportar clave pública
    public_key = key.publickey().export_key(format="PEM")

    # 4. Guardar archivos
    with open("private_key.pem", "wb") as f:
        f.write(private_key)

    with open("public_key.pem", "wb") as f:
        f.write(public_key)

    print("Claves generadas correctamente.")


if __name__ == '__main__':
    generar_par_claves(3072)
    print("Claves generadas: private_key.pem y public_key.pem")