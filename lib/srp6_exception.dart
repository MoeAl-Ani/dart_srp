enum CauseType { badPublicValue, badCredentials, timeout }
class SRP6Exception implements Exception {
  String message;
  CauseType causeType;

  SRP6Exception(this.message, this.causeType);
}