import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import crypto.AES;
import crypto.Crypto;
import crypto.HMAC;
import crypto.KeyGroup;
import crypto.KeyPair;
import crypto.RSA;

public class App {
    public static void main(String[] args) throws Exception {

        var r = new SecureRandom();
        System.out.println(BigInteger.probablePrime(128, r));

        // var keys = RSA.generateKeys();

        // var publicKeyPair = keys[0];
        // var privateKeyPair = keys[1];

        // SecretKey aesKey = AES.generateKey();

        // var keyGenerator = KeyGenerator.getInstance("HmacSHA1");

        // var hmacKey = keyGenerator.generateKey();

        // KeyGroup serverKeys = new KeyGroup(hmacKey, publicKeyPair, aesKey);
        // KeyGroup clientKeys = new KeyGroup(hmacKey, privateKeyPair, aesKey);

        // String encrypted = Crypto.encryptMessage("ola", clientKeys);

        // // System.out.println(encrypted);

        // String decrypted = Crypto.decryptMessage(encrypted, serverKeys);

        // // System.out.println(decrypted);

        // // System.out.println(HMAC.encrypt("ola", hmacKey));

        // byte[] rawData = hmacKey.getEncoded();
        // String encodedKey = Base64.getEncoder().encodeToString(rawData);
        // System.out.println(encodedKey);

        // String encrypted = Crypto.encryptFirstMessage("ola ", publicKeyPair);

        // String decrypted = Crypto.decryptFirstMessage(encrypted, privateKeyPair);
        // System.out.println(decrypted);

        // String decrypted = RSA.decrypt(encrypted, n, d);

        // System.out.println(decrypted);

        // // print char values of decrypted
        // for (int i = 0; i < decrypted.length(); i++) {
        // System.out.print((int) decrypted.charAt(i) + " ");
        // }

    }
}
