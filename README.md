# SRP (secure remote password) Java famous NIMBUS port 
Implementation based on the [RFC5054](https://tools.ietf.org/html/rfc5054) specification. See also the SRP description at [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol).

Only SHA-256 is currently supported, others are planned in the future.

## Routines
High-level description of the client-server interaction.

### Client routine
```dart
  SRP6CryptoParams config =
      SRP6CryptoParams.getInstance(bitsize: 256, H: "SHA-256");
  SRP6VerifierGenerator generator = SRP6VerifierGenerator(config);
  // CustomXRoutine is compatible with thinbus js
  generator.setXRoutine(CustomXRoutine(config.N));

  List<SrpUser> users = [];
  for (int i = 1; i <= 10000; i++) {
    BigInt salt = BigIntHelper.createRandomBigInt().abs();
    String username = randomString(15);
    String password = randomString(20);
    BigInt verifier = generator.generateVerifier(salt, username, password);
    users.add(SrpUser(i, username, password, salt, verifier));
  }

  for (var user in users) {
    /// step_one client
    SRP6ClientSession srp6clientSession = SRP6ClientSession();
    SRP6ServerSession srp6serverSession = SRP6ServerSession(config);
    srp6clientSession.setXRoutine(CustomXRoutine(config.N));
    srp6clientSession.step1(user.username, user.password);

    /// step_one server
    BigInt B = srp6serverSession.step1(user.username, user.salt, user.verifier);

    /// step_two client
    SRP6ClientCredentials credentials =
        srp6clientSession.step2(config, user.salt, B);

    /// step_two server
    try {
      BigInt M2 = srp6serverSession.step2(credentials.A!, credentials.M1!);
      srp6clientSession.step3(M2);
    } catch (err) {
      print("error: $err");
    }
```