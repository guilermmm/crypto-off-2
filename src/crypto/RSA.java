package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

  public static KeyPair[] generateKeys() {
    return generateKeys(false);
  }

  public static KeyPair[] generateKeys(Boolean server) {
    BigInteger p, q;
    if (server) {
      p = new BigInteger("179851167062238885404484306544234462027");
      q = new BigInteger("316847825231810394585704257062047161633");
    } else {
      p = generatePrimeNumber();
      q = generatePrimeNumber();
    }

    BigInteger n = p.multiply(q);
    BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

    BigInteger e = new BigInteger("65537");

    BigInteger d = e.modInverse(phi);

    var publicKey = new KeyPair(n, e);
    var privateKey = new KeyPair(n, d);

    return new KeyPair[] { publicKey, privateKey };
  }

  public static String encrypt(String message, KeyPair keyPair) {
    BigInteger[] ascii = new BigInteger[message.length()];
    for (int i = 0; i < message.length(); i++) {
      ascii[i] = new BigInteger(String.valueOf((int) message.charAt(i)));
    }

    BigInteger[] bigInts = new BigInteger[ascii.length];

    for (int i = 0; i < ascii.length; i++) {
      bigInts[i] = ascii[i].modPow(keyPair.keys[1], keyPair.keys[0]);
    }

    StringBuilder sb = new StringBuilder();
    for (BigInteger bigInt : bigInts) {
      sb.append(bigInt).append(" ");
    }

    return sb.toString();
  }

  public static String decrypt(String encryptedMessage, KeyPair keyPair) {

    String[] encryptedMessageArray = encryptedMessage.trim().split(" ");

    BigInteger[] ascii = new BigInteger[encryptedMessageArray.length];
    for (int i = 0; i < encryptedMessageArray.length; i++) {
      ascii[i] = new BigInteger(encryptedMessageArray[i]);
    }

    BigInteger[] bigInts = new BigInteger[ascii.length];

    for (int i = 0; i < ascii.length; i++) {
      bigInts[i] = ascii[i].modPow(keyPair.keys[1], keyPair.keys[0]);
    }

    StringBuilder sb = new StringBuilder();

    for (BigInteger bigInt : bigInts) {
      sb.append((char) bigInt.intValue());
    }

    return sb.toString();

  }

  private static BigInteger generatePrimeNumber() {
    var r = new SecureRandom();
    return BigInteger.probablePrime(128, r);
  }
}
