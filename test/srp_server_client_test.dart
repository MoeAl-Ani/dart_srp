import 'dart:convert';
import 'dart:math';

import 'package:dart_srp/custom_x_routine.dart';
import 'package:dart_srp/srp6_client_session.dart';
import 'package:dart_srp/srp6_crypto_params.dart';
import 'package:dart_srp/srp6_server_session.dart';
import 'package:dart_srp/srp6_verifier_generator.dart';
import 'package:test/test.dart';

void main() {
  late SRP6CryptoParams config;
  late SRP6VerifierGenerator generator;

  setUp(() {
    config = SRP6CryptoParams.getInstance(bitsize: 256, H: "SHA-256");
    generator = SRP6VerifierGenerator(config);
    generator.setXRoutine(CustomXRoutine(config.N));
  });

  test('full SRP handshake succeeds for 10000 users', () {
    List<SrpUser> users = [];
    for (int i = 1; i <= 10000; i++) {
      var saltStr = generator.generateRandomSalt(numBytes: 32);
      BigInt salt = BigInt.parse(utf8.decode(saltStr), radix: 10);
      String username = randomString(15);
      String password = randomString(20);
      BigInt verifier = generator.generateVerifier(salt, username, password);
      users.add(SrpUser(i, username, password, salt, verifier));
    }

    for (var user in users) {
      SRP6ClientSession srp6clientSession = SRP6ClientSession();
      SRP6ServerSession srp6serverSession = SRP6ServerSession(config);
      srp6clientSession.setXRoutine(CustomXRoutine(config.N));
      srp6clientSession.step1(user.username, user.password);

      BigInt B =
          srp6serverSession.step1(user.username, user.salt, user.verifier);

      var credentials = srp6clientSession.step2(config, user.salt, B);

      BigInt M2 =
          srp6serverSession.step2(credentials.A!, credentials.m1!);
      srp6clientSession.step3(M2);
    }
  });
}

String randomString(int strlen) {
  String chars = "äöéýỲabcdefghijklmnopqrstuvwxyz0123456789";
  Random rnd = Random(DateTime.now().millisecondsSinceEpoch);
  String result = "";
  for (var i = 0; i < strlen; i++) {
    result += chars[rnd.nextInt(chars.length)];
  }
  return result;
}

class SrpUser {
  int id;
  String username;
  String password;
  BigInt salt;
  BigInt verifier;

  SrpUser(this.id, this.username, this.password, this.salt, this.verifier);

  @override
  String toString() {
    return 'SrpUser{id: $id, username: $username, password: $password, salt: $salt, verifier: $verifier}';
  }
}
