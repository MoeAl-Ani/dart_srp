# SRP (secure remote password) Java famous NIMBUS port 
Implementation based on the [RFC5054](https://tools.ietf.org/html/rfc5054) specification. See also the SRP description at [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol).

Only SHA-256 is currently supported, others are planned in the future.

## Routines
High-level description of the client-server interaction.

### Client routine
```dart
  import 'dart:convert';
import 'dart:math';

import 'package:dart_srp/custom_x_routine.dart';
import 'package:dart_srp/srp6_client_credentials.dart';
import 'package:dart_srp/srp6_client_session.dart';
import 'package:dart_srp/srp6_crypto_params.dart';
import 'package:dart_srp/srp6_server_session.dart';
import 'package:dart_srp/srp6_verifier_generator.dart';


/// Srp server client test
///
/// author Mohammed Al-Ani
void main() {
  SRP6CryptoParams config =
  SRP6CryptoParams.getInstance(bitsize: 256, H: "SHA-256");
  SRP6VerifierGenerator generator = SRP6VerifierGenerator(config);
  generator.setXRoutine(CustomXRoutine(config.N));

  List<SrpUser> users = [];
  for (int i = 1; i <= 10000; i++) {
    var saltStr = generator.generateRandomSalt(numBytes: 32);
    BigInt salt = BigInt.parse(utf8.decode(saltStr), radix: 10);
    //BigInt salt = BigIntHelper.createRandomBigInt().abs();
    String username = randomString(15);
    String password = randomString(20);
    BigInt verifier = generator.generateVerifier(salt, username, password);
    users.add(SrpUser(i, username, password, salt, verifier));
  }

  for (var user in users) {
    /// stepone client
    SRP6ClientSession srp6clientSession = SRP6ClientSession();
    SRP6ServerSession srp6serverSession = SRP6ServerSession(config);
    srp6clientSession.setXRoutine(CustomXRoutine(config.N));
    srp6clientSession.step1(user.username, user.password);

    /// stepone server
    BigInt B = srp6serverSession.step1(user.username, user.salt, user.verifier);

    /// steptwo client

    SRP6ClientCredentials credentials =
    srp6clientSession.step2(config, user.salt, B);

    /// step two server
    try {
      BigInt M2 = srp6serverSession.step2(credentials.A!, credentials.m1!);
      srp6clientSession.step3(M2);
    } catch (err) {
      print("error: $err");
    }

    /// step3 client
  }
  print("test done without errors");
}

String randomString(int strlen) {
  String chars = "äöéýỲabcdefghijklmnopqrstuvwxyz0123456789";
  Random rnd = Random(DateTime
      .now()
      .millisecondsSinceEpoch);
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
```