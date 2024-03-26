package crypto;

import java.math.BigInteger;

public class KeyPair {
  BigInteger[] keys;

  public KeyPair(BigInteger k1, BigInteger k2) {
    keys = new BigInteger[] { k1, k2 };
  }

  public static KeyPair fromString(String key) {
    System.out.println(key);
    String[] parts = key.split(":");
    return new KeyPair(new BigInteger(parts[0]), new BigInteger(parts[1]));
  }

  public String toString() {
    return keys[0].toString() + ":" + keys[1].toString();
  }

}
