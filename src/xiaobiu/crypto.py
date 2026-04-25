from __future__ import annotations

import base64
from functools import lru_cache

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 苏宁AES加密密钥
SUNING_AES_KEY = b"www.cnsuning.com"
# 苏宁AES加密初始化向量(IV)
SUNING_AES_IV = b"moc.gninusnc.www"
# 标准Base64字母表
STANDARD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
# 苏宁自定义Base64字母表(将+/替换为())
SUNING_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()*"
# 标准Base64到苏宁Base64的转换映射
STANDARD_TO_SUNING_BASE64 = str.maketrans(
  STANDARD_BASE64_ALPHABET,
  SUNING_BASE64_ALPHABET,
)
# 苏宁Base64到标准Base64的转换映射
SUNING_TO_STANDARD_BASE64 = str.maketrans(
  SUNING_BASE64_ALPHABET,
  STANDARD_BASE64_ALPHABET,
)


def encode_suning_base64(raw: bytes) -> str:
  """使用苏宁自定义的Base64编码
  
  Args:
    raw: 原始字节数据
    
  Returns:
    苏宁Base64编码后的字符串
  """
  return base64.b64encode(raw).decode("ascii").translate(STANDARD_TO_SUNING_BASE64)


def decode_suning_base64(encoded: str) -> bytes:
  """解码苏宁自定义的Base64编码
  
  Args:
    encoded: 苏宁Base64编码的字符串
    
  Returns:
    解码后的原始字节数据
  """
  return base64.b64decode(encoded.translate(SUNING_TO_STANDARD_BASE64))


class SuAESCipher:
  """苏宁AES加密/解密类
  
  使用AES-CBC模式进行加密和解密，配合苏宁自定义的Base64编码
  """
  
  def __init__(self, key: bytes = SUNING_AES_KEY, iv: bytes = SUNING_AES_IV) -> None:
    """初始化AES加密器
    
    Args:
      key: AES加密密钥，默认使用苏宁的固定密钥
      iv: 初始化向量，默认使用苏宁的固定IV
    """
    self._key = key
    self._iv = iv

  def encrypt(self, plaintext: str) -> str:
    """加密明文字符串
    
    Args:
      plaintext: 待加密的明文字符串
      
    Returns:
      加密并Base64编码后的字符串
    """
    # 使用PKCS7填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    # 使用AES-CBC模式加密
    cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    # 使用苏宁自定义Base64编码
    return encode_suning_base64(encrypted)

  def decrypt(self, ciphertext: str) -> str:
    """解密密文字符串
    
    Args:
      ciphertext: 使用苏宁Base64编码的密文字符串
      
    Returns:
      解密后的明文字符串
    """
    # 使用AES-CBC模式解密
    cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(decode_suning_base64(ciphertext)) + decryptor.finalize()
    # 移除PKCS7填充
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()
    return plaintext.decode("utf-8")


@lru_cache(maxsize=8)
def _load_public_key(public_key_base64: str):
  """加载RSA公钥(带缓存)
  
  Args:
    public_key_base64: Base64编码的DER格式公钥
    
  Returns:
    RSA公钥对象
  """
  key_bytes = base64.b64decode(public_key_base64)
  return serialization.load_der_public_key(key_bytes)


def rsa_encrypt_base64(plaintext: str, public_key_base64: str) -> str:
  """使用RSA公钥加密并返回Base64编码结果
  
  Args:
    plaintext: 待加密的明文字符串
    public_key_base64: Base64编码的DER格式公钥
    
  Returns:
    Base64编码的加密结果
  """
  public_key = _load_public_key(public_key_base64)
  encrypted = public_key.encrypt(
    plaintext.encode("utf-8"),
    asymmetric_padding.PKCS1v15(),
  )
  return base64.b64encode(encrypted).decode("ascii")
