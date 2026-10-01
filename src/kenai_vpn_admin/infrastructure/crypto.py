import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


class EncryptionError(RuntimeError):
    pass


class FernetCipher:
    """Encrypts sensitive database fields with a deployment-provided key."""

    def __init__(self, configured_key: str | None, secret_key: str, *, allow_derived: bool) -> None:
        if configured_key:
            key = configured_key.encode("ascii")
        elif allow_derived:
            digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
            key = base64.urlsafe_b64encode(digest)
        else:
            raise RuntimeError("Production requires an explicit KENAI_ENCRYPTION_KEY")
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        try:
            return self._fernet.decrypt(ciphertext).decode("utf-8")
        except InvalidToken as exc:
            raise EncryptionError("Stored secret could not be decrypted") from exc
