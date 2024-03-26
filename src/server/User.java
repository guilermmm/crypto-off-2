package server;

public class User {
  String cpf, password, name, address, phone;
  int currentBalance, savingsBalance, fixedBalance;

  public User(String cpf, String password, String name, String address, String phone) {
    this.cpf = cpf;
    this.password = password;
    this.name = name;
    this.address = address;
    this.phone = phone;
    this.currentBalance = 0;
    this.savingsBalance = 0;
    this.fixedBalance = 0;
  }

  private float transformToFloat(int value) {
    return (float) value / 100;
  }

  private int transformToInt(float value) {
    return (int) (value * 100);
  }

  public Boolean withdraw(float value, String accountType) {
    int intValue = transformToInt(value);

    switch (accountType) {
      case "1":
        if (this.currentBalance < intValue)
          return false;
        this.currentBalance -= intValue;
        return true;

      case "2":
        if (this.savingsBalance < intValue)
          return false;
        this.savingsBalance -= intValue;
        return true;

      case "3":
        if (this.fixedBalance < intValue)
          return false;
        this.fixedBalance -= intValue;
        return true;
      default:
        return false;
    }
  }

  public void deposit(float value, String accountType) {
    int intValue = transformToInt(value);

    switch (accountType) {
      case "1":
        this.currentBalance += intValue;
        break;
      case "2":
        this.savingsBalance += intValue;
        break;
      case "3":
        this.fixedBalance += intValue;
        break;

      default:
        break;
    }
  }

  public String balance(String accountType) {
    switch (accountType) {
      case "1":
        return String.format("%.2f", transformToFloat(this.currentBalance));
      case "2":
        return String.format("%.2f", transformToFloat(this.savingsBalance));
      case "3":
        return String.format("%.2f", transformToFloat(this.fixedBalance));
      default:
        return "0";
    }
  }

  public Boolean transfer(User user, int value) {
    if (this.currentBalance < value)
      return false;

    this.currentBalance -= value;
    user.currentBalance += value;
    return true;
  }

  public float getCurrent() {
    return transformToFloat(this.currentBalance);
  }

  public float getSavings() {
    return transformToFloat(this.savingsBalance);
  }

  public float getFixed() {
    return transformToFloat(this.fixedBalance);
  }

}
