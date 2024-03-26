package crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AES {

  public static SecretKey generateKey() throws NoSuchAlgorithmException {
    var keyGenerator = KeyGenerator.getInstance("AES");
    return keyGenerator.generateKey();
  }

  public static String encrypt(String text, SecretKey key) {
    byte[] encryptedMessageBytes;
    Cipher encrypter;
    String encryptedMessage = "";
    String message = text;
    try {
      encrypter = Cipher
          .getInstance("AES/ECB/PKCS5Padding");
      encrypter.init(Cipher.ENCRYPT_MODE, key);
      encryptedMessageBytes = encrypter.doFinal(message.getBytes());
      encryptedMessage = Base64
          .getEncoder()
          .encodeToString(encryptedMessageBytes);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    }
    return encryptedMessage;
  }

  public static String decrypt(String text, SecretKey key) {
    // Decriptação
    byte[] encryptedMessageBytes = Base64
        .getDecoder()
        .decode(text);
    Cipher decriptador;
    String message = "";
    try {
      decriptador = Cipher.getInstance("AES/ECB/PKCS5Padding");
      decriptador.init(Cipher.DECRYPT_MODE, key);
      byte[] decryptedMessageBytes = decriptador.doFinal(encryptedMessageBytes);
      String decryptedMessage = new String(decryptedMessageBytes);
      /*
       * System.out.println("<< Mensagem decifrada = "
       * + mensagemDecifrada);
       */
      message = decryptedMessage;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    }
    return message;
  }
}
