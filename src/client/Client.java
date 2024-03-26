package client;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Scanner;

import crypto.B64;
import crypto.Crypto;
import crypto.HMAC;
import crypto.KeyGroup;
import crypto.KeyPair;
import crypto.RSA;
import dbg.Dbg;
import dbg.Dbg.Color;

public class Client implements Runnable {
  Boolean active = true;
  DatagramSocket clientSocket = null;
  Scanner sc = new Scanner(System.in);
  InetAddress address;
  byte[] sendBuffer;
  byte[] receiveBuffer;
  String token;
  Boolean logged = false;
  String accountNumber;
  KeyPair publicKey;
  KeyPair privateKey;
  KeyGroup keyGroup;
  Boolean attacker = false;

  public Client() {
    var keys = RSA.generateKeys();
    publicKey = keys[0];
    privateKey = keys[1];

    System.out.println("Public key: " + publicKey.toString());

    var serverKeys = RSA.generateKeys(true);

    keyGroup = new KeyGroup(serverKeys[0]);
    start();
  }

  public Client(Boolean attacker) {
    this.attacker = attacker;

    var keys = RSA.generateKeys();
    publicKey = keys[0];
    privateKey = keys[1];

    System.out.println("Public key: " + publicKey.toString());

    var serverKeys = RSA.generateKeys(true);

    keyGroup = new KeyGroup(serverKeys[0]);
    start();
  }

  private void start() {
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
      Dbg.log();
      clientSocket = new DatagramSocket();
      address = InetAddress.getByName("localhost");
      Dbg.log(Color.CYAN, "Cliente rodando em: " +
          InetAddress.getLocalHost() + ":" +
          clientSocket.getLocalPort() + "\n");

      sendFirstMessage();

      var firstMessage = receiveFirstMessage();

      if (firstMessage.contains("true")) {
        var parts = firstMessage.split(":");
        var hmac = KeyGroup.stringToKey(parts[1], "hmac");
        var aes = KeyGroup.stringToKey(parts[2], "aes");

        this.keyGroup.aesKey = aes;
        this.keyGroup.hmacKey = hmac;

        if (attacker)
          this.keyGroup.hmacKey = HMAC.generateKey();

        System.out.println(KeyGroup.keyToString(this.keyGroup.hmacKey));

        Dbg.log(Color.GREEN, "Conexão estabelecida com sucesso!");
      } else {
        Dbg.log(Color.RED, "Erro ao estabelecer conexão.");
        return;
      }

      while (active) {

        Dbg.log(Color.BLUE, "|--- Sistema do banco ---|");

        if (!logged) {
          Dbg.log(Color.BLUE, "1. Login");
          Dbg.log(Color.BLUE, "2. Cadastrar");
        } else {
          Dbg.log(Color.BLUE, "1. Saque");
          Dbg.log(Color.BLUE, "2. Depósito");
          Dbg.log(Color.BLUE, "3. Transferência");
          Dbg.log(Color.BLUE, "4. Saldo");
          Dbg.log(Color.BLUE, "5. Investimentos");
          Dbg.log(Color.BLUE, "6. Sair");
        }
        String msg = sc.nextLine().trim();

        switch (msg) {

          case "1":
            if (!logged) {
              login();
            } else {
              withdraw();
            }
            break;
          case "2":
            if (!logged) {
              signUp();
            } else {
              deposit();
            }
            break;
          case "3":
            if (logged) {
              transfer();
            } else {
              Dbg.log(Color.RED, "Comando inválido");
            }
            break;
          case "4":
            if (logged) {
              balance();
            }
            break;
          case "5":
            if (logged) {
              investment();
            } else {
              Dbg.log(Color.RED, "Comando inválido");
            }
            break;
          case "6":
            if (logged) {

              logged = false;
              accountNumber = "";
            } else {
              Dbg.log(Color.RED, "Comando inválido");
            }
            break;

          case "sair":
            active = false;
            Dbg.log(Color.RED, "Cliente encerrado");
            break;
          default:
            Dbg.log();
            Dbg.log(Color.RED, "Comando inválido");
            break;
        }

      }
    } catch (SocketException e) {
      System.out.println("Socket: " + e.getMessage());
    } catch (IOException e) {
      System.out.println("IO: " + e.getMessage());
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      if (clientSocket != null)
        clientSocket.close();
      sc.close();
    }
  }

  public void login() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Login ---|");
    Dbg.log(Color.YELLOW, "Digite o número da conta:");
    String accountNumber = sc.nextLine();
    Dbg.log(Color.YELLOW, "Digite a senha:");
    String password = sc.nextLine();

    sendMessage("login/" + accountNumber + ":" + password);

    String response = receiveMessage();

    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.equals("true")) {
      Dbg.log(Color.GREEN, "Usuário autenticado com sucesso!");
      logged = true;
      this.accountNumber = accountNumber;
    } else {
      Dbg.log(Color.RED, "Número da conta e/ou senha incorretos.");
    }
  }

  public void signUp() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Cadastro ---|");
    Dbg.log(Color.YELLOW, "Digite o nome:");
    String name = sc.nextLine();
    Dbg.log(Color.YELLOW, "Digite o CPF:");
    String cpf = sc.nextLine();
    Dbg.log(Color.YELLOW, "Digite a senha:");
    String password = sc.nextLine();
    Dbg.log(Color.YELLOW, "Digite o endereço:");
    String address = sc.nextLine();
    Dbg.log(Color.YELLOW, "Digite o telefone:");
    String phone = sc.nextLine();
    String msg = "signup/" + name + ":" + cpf + ":" + password + ":" + address + ":" + phone;

    sendMessage(msg);

    String response = receiveMessage();

    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.contains("true")) {
      String accountNumber = response.split(":")[1];
      Dbg.log(Color.GREEN, "Usuário cadastrado com sucesso!\nFaça login com o número da conta " + accountNumber
          + " e a senha cadastrada.");
    } else {
      Dbg.log(Color.RED, "Erro ao cadastrar usuário.");
    }
  }

  public void withdraw() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Saque ---|");

    String accountType = "";
    do {
      if (accountType != "") {
        Dbg.log(Color.RED, "Tipo de conta inválido.");
      }
      Dbg.log(Color.YELLOW, "Selecione o tipo de conta:");
      Dbg.log(Color.YELLOW, "1. Conta corrente");
      Dbg.log(Color.YELLOW, "2. Conta poupança");
      Dbg.log(Color.YELLOW, "3. Renda fixa");
      accountType = sc.nextLine();
    } while (!accountType.equals("1") && !accountType.equals("2") && !accountType.equals("3"));

    String value;

    while (true) {
      try {
        Dbg.log(Color.YELLOW, "Digite o valor do saque:");
        String inputValue = sc.nextLine();
        value = String.format("%.2f", Float.parseFloat(inputValue));
        break;
      } catch (NumberFormatException e) {
        Dbg.log(Color.RED, "Valor inválido.");
      }
    }

    sendMessage("withdraw/" + accountNumber + ":" + accountType + ":" + value);
    String response = receiveMessage();
    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.equals("true")) {
      Dbg.log(Color.GREEN, "Saque realizado com sucesso!");
    } else {
      Dbg.log(Color.RED, "Erro ao realizar saque.");
      Dbg.log(Color.RED, response);
    }
  }

  public void deposit() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Depósito ---|");

    String accountType = "";
    do {
      if (accountType != "") {
        Dbg.log(Color.RED, "Tipo de conta inválido.");
      }
      Dbg.log(Color.YELLOW, "Selecione o tipo de conta:");
      Dbg.log(Color.YELLOW, "1. Conta corrente");
      Dbg.log(Color.YELLOW, "2. Conta poupança");
      Dbg.log(Color.YELLOW, "3. Renda fixa");
      accountType = sc.nextLine();
    } while (!accountType.equals("1") && !accountType.equals("2") && !accountType.equals("3"));

    String value;

    while (true) {
      try {
        Dbg.log(Color.YELLOW, "Digite o valor do depósito:");
        String inputValue = sc.nextLine();
        value = String.format("%.2f", Float.parseFloat(inputValue));
        break;
      } catch (NumberFormatException e) {
        Dbg.log(Color.RED, "Valor inválido.");
      }
    }

    sendMessage("deposit/" + accountNumber + ":" + accountType + ":" + value);
    String response = receiveMessage();
    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.equals("true")) {
      Dbg.log(Color.GREEN, "Depósito realizado com sucesso!");
    } else {
      Dbg.log(Color.RED, "Erro ao realizar depósito.");
    }
  }

  public void transfer() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Transferência ---|");

    String destinationNumber = "";

    do {
      if (destinationNumber.equals(this.accountNumber)) {
        Dbg.log(Color.RED, "Você não pode transferir para a sua própria conta.");
      }
      Dbg.log(Color.YELLOW, "Digite o número da conta de destino:");
      destinationNumber = sc.nextLine();
    } while (destinationNumber.equals(this.accountNumber));

    String value;

    while (true) {
      try {
        Dbg.log(Color.YELLOW, "Digite o valor da transferência:");
        String inputValue = sc.nextLine();
        value = String.format("%.2f", Float.parseFloat(inputValue));
        break;
      } catch (NumberFormatException e) {
        Dbg.log(Color.RED, "Valor inválido.");
      }
    }

    sendMessage("transfer/" + this.accountNumber + ":" + destinationNumber + ":" + value);
    String response = receiveMessage();
    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.equals("true")) {
      Dbg.log(Color.GREEN, "Transferência realizada com sucesso!");
    } else {
      Dbg.log(Color.RED, response);
    }
  }

  public void balance() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Saldo ---|");

    String accountType = "";
    do {
      if (accountType != "") {
        Dbg.log(Color.RED, "Tipo de conta inválido.");
      }
      Dbg.log(Color.YELLOW, "Selecione o tipo de conta:");
      Dbg.log(Color.YELLOW, "1. Conta corrente");
      Dbg.log(Color.YELLOW, "2. Conta poupança");
      Dbg.log(Color.YELLOW, "3. Renda fixa");
      accountType = sc.nextLine();
    } while (!accountType.equals("1") && !accountType.equals("2") && !accountType.equals("3"));

    sendMessage("balance/" + accountNumber + ":" + accountType);
    String response = receiveMessage();
    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.contains("R$")) {
      String accountName = accountType.equals("1") ? "Conta corrente"
          : accountType.equals("2") ? "Conta poupança" : "Renda fixa";
      Dbg.log(Color.GREEN, "Saldo da conta " + accountName + ": " + response + "\n");
    } else {
      Dbg.log(Color.RED, "Erro ao consultar saldo.");
    }
  }

  public void investment() throws Exception {
    Dbg.log();
    Dbg.log(Color.BLUE, "|--- Investimentos ---|");

    String accountType = "";
    do {
      if (accountType != "") {
        Dbg.log(Color.RED, "Tipo de conta inválido.");
      }
      Dbg.log(Color.YELLOW, "Selecione o tipo de conta:");
      Dbg.log(Color.YELLOW, "2. Conta poupança");
      Dbg.log(Color.YELLOW, "3. Renda fixa");
      accountType = sc.nextLine();
    } while (!accountType.equals("2") && !accountType.equals("3"));

    sendMessage("investment/" + accountNumber + ":" + accountType);
    String response = receiveMessage();
    Dbg.log();

    try {
      response = Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return;
    }

    if (response.contains("R$")) {
      if (accountType.equals("2")) {
        Dbg.log(Color.GREEN, "Saldo da conta poupança: " + response + "\n");

        var balance = Float.parseFloat(response.split("R\\$")[1].trim());

        var interest3 = balance * 0.5f / 100 * 3;
        var interest6 = balance * 0.5f / 100 * 6;
        var interest12 = balance * 0.5f / 100 * 12;

        Dbg.log(Color.GREEN, "Rendimento da poupança em 3 meses: R$" + String.format("%.2f", interest3));
        Dbg.log(Color.GREEN, "Rendimento da poupança em 6 meses: R$" + String.format("%.2f", interest6));
        Dbg.log(Color.GREEN, "Rendimento da poupança em 12 meses: R$" + String.format("%.2f", interest12) + "\n");
      } else {
        Dbg.log(Color.GREEN, "Saldo da renda fixa: " + response + "\n");

        var balance = Float.parseFloat(response.split("R\\$")[1].trim());

        var interest3 = balance * 1.5f / 100 * 3;
        var interest6 = balance * 1.5f / 100 * 6;
        var interest12 = balance * 1.5f / 100 * 12;

        Dbg.log(Color.GREEN, "Rendimento da renda fixa em 3 meses: R$" + String.format("%.2f", interest3));
        Dbg.log(Color.GREEN, "Rendimento da renda fixa em 6 meses: R$" + String.format("%.2f", interest6));
        Dbg.log(Color.GREEN, "Rendimento da renda fixa em 12 meses: R$" + String.format("%.2f", interest12) + "\n");
      }
    } else {
      Dbg.log(Color.RED, "Erro ao consultar saldo.");
    }
  }

  private void sendFirstMessage() throws Exception {
    sendBuffer = new byte[1024];
    sendBuffer = B64.encode(Crypto.encryptFirstMessage("start:" + publicKey.toString(),
        keyGroup.rsaKeyPair)).getBytes();

    DatagramPacket sendDatagram = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        address,
        5050);

    clientSocket.send(sendDatagram);
  }

  private String receiveFirstMessage() throws Exception {
    receiveBuffer = new byte[10240];

    DatagramPacket receiveDatagram = new DatagramPacket(
        receiveBuffer,
        receiveBuffer.length);
    clientSocket.receive(receiveDatagram);
    receiveBuffer = receiveDatagram.getData();

    try {
      return Crypto.decryptFirstMessage(B64.decode(new String(receiveBuffer)), privateKey);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return null;
    }
  }

  private void sendMessage(String message) throws Exception {
    sendBuffer = new byte[1024];
    String msg = Crypto.encryptMessage(message, keyGroup, privateKey);
    sendBuffer = msg.getBytes();
    DatagramPacket sendDatagram = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        address,
        5050);

    clientSocket.send(sendDatagram);
  }

  private String receiveMessage() throws Exception {
    receiveBuffer = new byte[10240];

    DatagramPacket receiveDatagram = new DatagramPacket(
        receiveBuffer,
        receiveBuffer.length);
    clientSocket.receive(receiveDatagram);
    receiveBuffer = receiveDatagram.getData();

    try {
      return Crypto.decryptMessage(new String(receiveBuffer), keyGroup);
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      System.out.println("AAAAAAAAAAAAAAAAAAA");
      return null;
    }
  }

}