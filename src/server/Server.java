package server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Hashtable;

import crypto.AES;
import crypto.B64;
import crypto.Crypto;
import crypto.HMAC;
import crypto.KeyGroup;
import crypto.KeyPair;
import crypto.RSA;
import dbg.Dbg;
import dbg.Dbg.Color;

public class Server implements Runnable {
  DatagramSocket serverSocket = null;
  InetAddress host;
  int port;
  Boolean active = true;
  byte[] receiveBuffer;
  byte[] sendBuffer;
  String message;
  String response;
  DatagramPacket receiveDatagram;
  DatagramPacket sendPacket;
  Hashtable<String, User> users;
  Hashtable<String, KeyGroup> clients;
  KeyPair publicKey;
  KeyPair privateKey;

  public Server(int port) {
    users = new Hashtable<String, User>();
    clients = new Hashtable<String, KeyGroup>();
    var keys = RSA.generateKeys(true);
    publicKey = keys[0];
    privateKey = keys[1];

    User u = new User("123.123.123-12", "123", "Cayo Perico", "Rua das Oiticicas, 33", "(84) 91236-4432");
    u.deposit(10000.00f, "1");

    users.put("1", u);
    users.put("2", new User("123.123.123-12", "123", "Jão Mouras", "Rua das Seticicas, 44", "(84) 91236-4432"));
    users.put("3", new User("123.123.123-12", "123", "Henri Theus", "Rua das Novicicas, 55", "(84) 91236-4432"));

    this.port = port;
    Thread t = new Thread(this);
    t.start();

    try {
      t.join();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  public void run() {
    try {
      serverSocket = new DatagramSocket(port);
      host = InetAddress.getLocalHost();
      Dbg.log();
      Dbg.log(Color.PURPLE, "Servidor online em: " +
          host +
          ":" +
          port);

      while (active) {
        var res = receiveMessage();

        if (res == null) {
          Dbg.log(Color.RED, "Cliente possivelmente atacante, ignorando...");
          sendMessage("false");
          continue;
        }

        String message = res[0];

        if (message == null) {
          Dbg.log(Color.RED, "Mensagem não autenticada.");
          sendMessage("false");
          continue;
        }

        if (message == "new") {
          continue;
        }

        String port = res[1];

        KeyGroup keyGroup = clients.get(port);

        Dbg.log(Color.BLUE, "Servidor recebeu a mensagem: " + message);

        String[] parted = message.split("/");
        String route = parted[0];
        String[] params = parted[1].split(":");

        switch (route) {
          case "login":
            login(params[0], params[1], keyGroup);
            break;
          case "signup":
            signUp(params[0], params[1], params[2], params[3], params[4], keyGroup);
            break;
          case "withdraw":
            withdraw(params[0], params[1], params[2], keyGroup);
            break;
          case "deposit":
            deposit(params[0], params[1], params[2], keyGroup);
            break;
          case "balance":
            response = balance(params[0], params[1]);
            sendMessage(response, keyGroup);
            break;
          case "transfer":
            response = transfer(params[0], params[1], params[2]);
            sendMessage(response, keyGroup);
            break;
          case "investment":
            response = investment(params[0], params[1]);
            sendMessage(response, keyGroup);
            break;

          default:
            continue;
        }

      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      // Fechando o servidor.
      if (serverSocket != null)
        serverSocket.close();
    }
  }

  public void login(String accountNumber, String password, KeyGroup keyGroup) throws Exception {
    User user = users.get(accountNumber);

    if (user == null || !user.password.equals(password)) {
      sendMessage("false", keyGroup);
      return;
    }

    sendMessage("true", keyGroup);
  }

  public void signUp(String name, String cpf, String password, String address, String phone, KeyGroup keyGroup)
      throws Exception {
    String accountNumber = String.valueOf(users.size() + 1);

    users.put(accountNumber, new User(cpf, password, name, address, phone));

    sendMessage("true:" + accountNumber, keyGroup);
  }

  public void withdraw(String accountNumber, String accountType, String value, KeyGroup keyGroup) throws Exception {
    User user = users.get(accountNumber);

    if (user == null) {
      sendMessage("Usuário não existe.", keyGroup);
      return;
    }

    Boolean w = user.withdraw(Float.parseFloat(value), accountType);

    if (!w) {
      sendMessage("Saldo insuficiente.", keyGroup);
      return;
    }

    sendMessage("true", keyGroup);
  }

  public void deposit(String accountNumber, String accountType, String value, KeyGroup keyGroup) throws Exception {
    User user = users.get(accountNumber);

    if (user == null) {
      sendMessage("Usuário não existe.", keyGroup);
      return;
    }

    user.deposit(Float.parseFloat(value), accountType);

    sendMessage("true", keyGroup);
  }

  public String transfer(String accountNumber, String destinationNumber, String value) {
    User user = users.get(accountNumber);
    User destinationUser = users.get(destinationNumber);

    if (user == null)
      return "Usuário não existe.";

    if (destinationUser == null)
      return "Usuário de destino não existe.";

    Boolean w = user.withdraw(Float.parseFloat(value), "1");

    if (!w)
      return "Saldo insuficiente.";

    destinationUser.deposit(Float.parseFloat(value), "1");

    return "true";
  }

  public String balance(String accountNumber, String accountType) {
    User user = users.get(accountNumber);

    if (user == null) {
      return "Usuário não existe.";
    }

    return "R$" + user.balance(accountType);
  }

  public String investment(String accountNumber, String accountType) {
    User user = users.get(accountNumber);

    if (user == null) {
      return "Usuário não existe.";
    }

    return "R$" + user.balance(accountType);
  }

  private String[] receiveMessage() throws Exception {
    receiveBuffer = new byte[10240];
    receiveDatagram = new DatagramPacket(
        receiveBuffer,
        receiveBuffer.length);
    serverSocket.receive(receiveDatagram);
    receiveBuffer = receiveDatagram.getData();

    String port = String.valueOf(receiveDatagram.getPort());

    if (!clients.containsKey(port)) {
      var decryptedFirstMessage = Crypto.decryptFirstMessage(B64.decode(new String(receiveBuffer)), privateKey);

      if (decryptedFirstMessage.contains("start")) {

        var clientPublicKey = decryptedFirstMessage.substring(6);

        System.out.println(clientPublicKey);

        var hmacKey = HMAC.generateKey();
        var aesKey = AES.generateKey();
        var keyGroup = new KeyGroup(hmacKey, KeyPair.fromString(clientPublicKey), aesKey);

        clients.put(port, keyGroup);

        sendFirstMessage("true:" + keyGroup.toString(), keyGroup.rsaKeyPair);

        return new String[] { "new" };
      }

      sendMessage("false");
      return null;
    }

    try {
      String decryptedMessage = Crypto.decryptMessage(new String(receiveBuffer), clients.get(port));
      return new String[] { decryptedMessage, port };
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return null;
    }
  }

  private void sendMessage(String message, KeyGroup keyGroup) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem - \"" + message + "\"");
    String response = Crypto.encryptMessage(message, keyGroup, privateKey);
    sendBuffer = response.getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        receiveDatagram.getPort());
    serverSocket.send(sendPacket);
  }

  private void sendMessage(String message) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem - \"" + message + "\"");
    sendBuffer = message.getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        receiveDatagram.getPort());
    serverSocket.send(sendPacket);
  }

  private void sendFirstMessage(String message, KeyPair keyPair) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem - \"" + message + "\"");
    String response = B64.encode(Crypto.encryptFirstMessage(message, keyPair));
    sendBuffer = response.getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        receiveDatagram.getPort());
    serverSocket.send(sendPacket);
  }

}
