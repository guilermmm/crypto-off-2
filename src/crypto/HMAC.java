package crypto;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class HMAC {
  public static final String ALG = "HmacSHA256";
  // public static final String ALG = "HmacSHA224";
  // public static final String ALG = "HmacSHA384";
  // public static final String ALG = "HmacSHA512";

  public static SecretKey generateKey() throws NoSuchAlgorithmException {
    var keyGenerator = KeyGenerator.getInstance("HmacSHA256");
    return keyGenerator.generateKey();
  }

  public static String encrypt(String message, SecretKey key) throws Exception {
    Mac shaHMAC = Mac.getInstance(ALG);
    shaHMAC.init(key);
    byte[] bytesHMAC = shaHMAC
        .doFinal(message.getBytes("UTF-8"));
    return byte2Hex(bytesHMAC);
  }

  public static String byte2Hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes)
      sb.append(String.format("%02x", b));
    return sb.toString();
  }
}
