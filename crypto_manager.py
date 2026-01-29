import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()

    # --- UTILIDADES PARA CLAVES ---
    def generate_key_pair(self):
        """Genera un par de llaves RSA (Privada y Pública)"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_private_key(self, private_key, password: str):
        """Convierte la llave privada a texto, CIFRÁNDOLA con tu password"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

    def load_private_key(self, pem_data: bytes, password: str):
        """Recupera la llave privada usando tu password"""
        return serialization.load_pem_private_key(pem_data, password=password.encode())

    def serialize_public_key(self, public_key):
        """Convierte la llave pública a texto para subirla al server"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_public_key(self, pem_data: bytes):
        return serialization.load_pem_public_key(pem_data)

    # --- CIFRADO HÍBRIDO (RSA + AES) ---

    def encrypt_bytes_for_user(self, data: bytes, recipient_public_key_pem: bytes) -> bytes:
        """
        NUEVO: Cifra bytes directamente (para texto o archivos en memoria).
        1. Crea llave de sesión (AES).
        2. Cifra los datos con AES.
        3. Cifra la llave de sesión con RSA (Llave Pública del destino).
        """
        # 1. Generar llave de sesión efímera (AES-256)
        session_key = os.urandom(32)
        nonce = os.urandom(12)

        # 2. Cifrar los datos con AES
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # 3. Cifrar la Session Key con RSA
        recipient_public_key = self.load_public_key(recipient_public_key_pem)
        encrypted_session_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Empaquetamos: [LargoKey][KeyCifrada][Nonce][Tag][DatosCifrados]
        return len(encrypted_session_key).to_bytes(4, 'big') + encrypted_session_key + nonce + encryptor.tag + ciphertext

    def encrypt_for_user(self, file_path: str, recipient_public_key_pem: bytes):
        """Lee un archivo del disco y lo cifra usando la función anterior"""
        with open(file_path, "rb") as f:
            file_data = f.read()
        return self.encrypt_bytes_for_user(file_data, recipient_public_key_pem)

    def decrypt_bytes(self, encrypted_data: bytes, my_private_key) -> bytes:
        """
        Descifra cualquier paquete de datos (sea archivo o texto).
        1. Extrae la Session Key cifrada.
        2. La descifra con TU Llave Privada RSA.
        3. Usa la Session Key para descifrar el contenido AES.
        """
        # Desempaquetar estructura
        key_len = int.from_bytes(encrypted_data[:4], 'big')
        encrypted_session_key = encrypted_data[4 : 4+key_len]
        nonce = encrypted_data[4+key_len : 4+key_len+12]
        tag = encrypted_data[4+key_len+12 : 4+key_len+12+16]
        ciphertext = encrypted_data[4+key_len+12+16 :]

        # 1. Recuperar la Session Key (AES) usando RSA
        session_key = my_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # 2. Descifrar el contenido
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def decrypt_file(self, encrypted_data: bytes, my_private_key) -> bytes:
        """Alias para mantener compatibilidad con código anterior"""
        return self.decrypt_bytes(encrypted_data, my_private_key)
    def sign_data(self, data: bytes, my_private_key) -> bytes:
        """Crea una firma digital para los datos usando tu llave privada"""
        signature = my_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data: bytes, signature: bytes, sender_public_key_pem: bytes) -> bool:
        """Verifica si la firma corresponde a los datos y al remitente"""
        try:
            sender_public_key = self.load_public_key(sender_public_key_pem)
            sender_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True # Firma válida
        except Exception:
            return False # Firma inválida (o datos alterados)