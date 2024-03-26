package crypto;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyGroup {
  public SecretKey hmacKey, aesKey;
  public KeyPair rsaKeyPair;

  public KeyGroup(SecretKey hmacKey, KeyPair rsaKeyPair, SecretKey aesKey) {
    this.hmacKey = hmacKey;
    this.rsaKeyPair = rsaKeyPair;
    this.aesKey = aesKey;
  }

  public KeyGroup(KeyPair rsaKeyPair) {
    this.rsaKeyPair = rsaKeyPair;
  }

  public String toString() {
    return keyToString(hmacKey) + ":" + keyToString(aesKey);
  }

  public static String keyToString(SecretKey key) {
    byte[] rawData = key.getEncoded();
    String encodedKey = Base64.getEncoder().encodeToString(rawData);
    return encodedKey;
  }

  public static SecretKey stringToKey(String key, String type) {
    byte[] decodedKey = Base64.getDecoder().decode(key);
    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, type == "aes" ? "AES" : "HmacSHA256");
    return originalKey;
  }

}
