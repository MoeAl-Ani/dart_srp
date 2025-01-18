
import 'dart:convert';

import 'bigInt_helper.dart';
import 'srp6_crypto_params.dart';
import 'srp6_routines.dart';
import 'xroutine.dart';

class SRP6VerifierGenerator {

  SRP6CryptoParams? config;
  XRoutine? xRoutine;

  SRP6VerifierGenerator(SRP6CryptoParams this.config);

  List<int> generateRandomSalt({final int numBytes = 16}) {

    return SRP6Routines.generateRandomSalt(numBytes);
  }

  void setXRoutine(final XRoutine routine) {

    xRoutine = routine;
  }

  XRoutine? getXRoutine() {

    return xRoutine;
  }

  BigInt _generateVerifier(final List<int> salt, final List<int> userID, final List<int> password) {
  BigInt x;

  if (xRoutine != null) {
  x = xRoutine!.computeX(config!.getMessageDigestInstance(),
  salt,
  userID,
  password);
  }
  else {
  x = SRP6Routines.computeX(config!.getMessageDigestInstance(), salt, password);
  }

  return SRP6Routines.computeVerifier(config!.N, config!.g, x);
  }

  BigInt generateVerifier(final BigInt salt, final String userID, final String password) {
    List<int> userIDBytes = List<int>.empty();

    userIDBytes = utf8.encode(userID);

    List<int> passwordBytes = utf8.encode(password);

    List<int> saltBytes = BigIntHelper.toByteArray(salt);
    if (saltBytes[0] == 0) {
      List<int> tmp = List.filled(saltBytes.length - 1, 0);
      BigIntHelper.arrayCopy(saltBytes, 1, tmp, 0, tmp.length);
      saltBytes = tmp;
    }

    return _generateVerifier(saltBytes, userIDBytes, passwordBytes);
  }
}
