package crypto;

public class Crypto {
  static String splitter = "&&::&&";

  public static String encryptFirstMessage(String message, KeyPair keyPair) {
    return RSA.encrypt(message, keyPair);
  }

  public static String decryptFirstMessage(String message, KeyPair keyPair) {
    return RSA.decrypt(message, keyPair);
  }

  public static String encryptMessage(String message, KeyGroup keyGroup, KeyPair privateKey) throws Exception {
    String encryptedMessage = AES.encrypt(message, keyGroup.aesKey);
    String hash = HMAC.encrypt(encryptedMessage, keyGroup.hmacKey);
    String encryptedHash = RSA.encrypt(hash, privateKey);
    String finalMessage = B64.encode(encryptedMessage + splitter + encryptedHash);
    return finalMessage;
  }

  public static String decryptMessage(String message, KeyGroup keyGroup) throws Exception {
    String[] parts = B64.decode(message).split(splitter);
    String encryptedMessage = parts[0];
    String encryptedHash = parts[1];

    String hash = RSA.decrypt(encryptedHash, keyGroup.rsaKeyPair);

    System.out.println(hash);

    String generatedHash = HMAC.encrypt(encryptedMessage, keyGroup.hmacKey);

    if (!hash.equals(generatedHash)) {
      throw new Exception("Hashes do not match");
    }

    return AES.decrypt(encryptedMessage, keyGroup.aesKey);
  }
}
