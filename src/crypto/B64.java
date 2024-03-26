package crypto;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class B64 {
  public static String encode(String msg) {
    byte[] bytesMsg = msg.getBytes();
    String msgBase64 = Base64
        .getEncoder()
        .encodeToString(bytesMsg);
    return msgBase64;
  }

  public static String decode(String msgBase64) throws UnsupportedEncodingException {
    byte[] bytesMsg = Base64
        .getDecoder()
        .decode(msgBase64.trim());
    String msg = new String(bytesMsg, "UTF-8");
    return msg;
  }

}
