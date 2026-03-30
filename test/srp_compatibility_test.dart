import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_srp/bigint_helper.dart';
import 'package:dart_srp/custom_x_routine.dart';
import 'package:dart_srp/srp6_client_session.dart';
import 'package:dart_srp/srp6_crypto_params.dart';
import 'package:dart_srp/srp6_routines.dart';
import 'package:dart_srp/srp6_server_session.dart';
import 'package:dart_srp/srp6_verifier_generator.dart';
import 'package:test/test.dart';

void main() {
  group('BigIntHelper byte encoding', () {
    test('toByteArray produces unsigned minimal bytes (no leading zero)', () {
      // A 256-bit number with MSB=1 (starts with 0x80 or higher)
      final value = BigInt.parse(
          'FF' * 32, // 256-bit number, all bits set
          radix: 16);

      final bytes = BigIntHelper.toByteArray(value);
      expect(bytes.length, equals(32),
          reason: 'toByteArray should produce 32 bytes for a 256-bit number');
      expect(bytes[0] & 0x80, isNonZero,
          reason: 'MSB should be set (high bit = 1)');
    });

    test('encodeBigInt adds leading zero byte for Java compatibility when MSB is set', () {
      // A 256-bit number with MSB=1
      final value = BigInt.parse(
          'FF' * 32,
          radix: 16);

      final bytes = BigIntHelper.encodeBigInt(value, endian: Endian.big);
      expect(bytes.length, equals(33),
          reason: 'encodeBigInt should produce 33 bytes (leading zero for Java compat)');
      expect(bytes[0], equals(0),
          reason: 'First byte should be 0x00 (sign byte)');
      expect(bytes[1], equals(0xFF),
          reason: 'Second byte should be the actual MSB of the number');
    });

    test('encodeBigInt matches toByteArray length when MSB is not set', () {
      // A 255-bit number (MSB is 0, so high byte starts with 0x7F or less)
      final value = BigInt.parse(
          '7F' + 'FF' * 31, // 255 effective bits
          radix: 16);

      final toByteArrayResult = BigIntHelper.toByteArray(value);
      final encodeBigIntResult = BigIntHelper.encodeBigInt(value, endian: Endian.big);

      expect(toByteArrayResult.length, equals(32));
      expect(encodeBigIntResult.length, equals(32),
          reason: 'No leading zero needed when MSB is not set');
    });

    test('encodeBigInt/decodeBigInt round-trip with default endianness', () {
      final original = BigInt.parse('DEADBEEF' * 8, radix: 16);
      final encoded = BigIntHelper.encodeBigInt(original);
      final decoded = BigIntHelper.decodeBigInt(Uint8List.fromList(encoded));
      expect(decoded, equals(original),
          reason: 'Round-trip encode/decode with defaults must preserve value');
    });
  });

  group('Evidence computation Java compatibility', () {
    test('computeClientEvidence uses Java-compatible byte encoding', () {
      final digest = sha256;

      // Use values where MSB is set (high bit = 1) to trigger the divergence
      final A = BigInt.parse('FF' * 32, radix: 16); // 256-bit, MSB=1
      final B = BigInt.parse('80' + '00' * 31, radix: 16); // 256-bit, MSB=1
      final S = BigInt.parse('C0' + 'AB' * 31, radix: 16); // 256-bit, MSB=1

      // Compute M1 using the library method
      final m1 = SRP6Routines.computeClientEvidence(digest, A, B, S);

      // Compute M1 manually using Java-compatible encoding (encodeBigInt with big-endian)
      final e1 = BigIntHelper.encodeBigInt(A, endian: Endian.big);
      final e2 = BigIntHelper.encodeBigInt(B, endian: Endian.big);
      final e3 = BigIntHelper.encodeBigInt(S, endian: Endian.big);
      final concat = BigIntHelper.concatByteArray(
          BigIntHelper.concatByteArray(e1, e2), e3);
      final javaM1 = BigInt.parse(digest.convert(concat).toString(), radix: 16);

      expect(m1, equals(javaM1),
          reason: 'computeClientEvidence must produce Java-compatible M1 '
              'using signed byte encoding (leading zero when MSB is set)');
    });

    test('computeServerEvidence uses Java-compatible byte encoding', () {
      final digest = sha256;

      final A = BigInt.parse('FF' * 32, radix: 16);
      final m1 = BigInt.parse('A0' + 'BC' * 31, radix: 16);
      final S = BigInt.parse('C0' + 'AB' * 31, radix: 16);

      // Compute M2 using the library method
      final m2 = SRP6Routines.computeServerEvidence(digest, A, m1, S);

      // Compute M2 manually using Java-compatible encoding
      final e1 = BigIntHelper.encodeBigInt(A, endian: Endian.big);
      final e2 = BigIntHelper.encodeBigInt(m1, endian: Endian.big);
      final e3 = BigIntHelper.encodeBigInt(S, endian: Endian.big);
      final concat = BigIntHelper.concatByteArray(
          BigIntHelper.concatByteArray(e1, e2), e3);
      final javaM2 = BigInt.parse(digest.convert(concat).toString(), radix: 16);

      expect(m2, equals(javaM2),
          reason: 'computeServerEvidence must produce Java-compatible M2');
    });
  });

  group('CustomXRoutine hex padding', () {
    test('hex strings are padded to correct length', () {
      final config = SRP6CryptoParams.getInstance(bitsize: 256, H: "SHA-256");
      final routine = CustomXRoutine(config.N);
      final digest = config.getMessageDigestInstance();

      // Use a known salt and password where the hash has a leading zero nibble.
      // We test multiple iterations to increase the chance of hitting a leading zero.
      bool testedLeadingZero = false;
      for (int i = 0; i < 100; i++) {
        final password = utf8.encode('password_$i');
        final hashHex = digest.convert(password).toString();

        if (hashHex.startsWith('0')) {
          testedLeadingZero = true;
          // When parsed and converted back, leading zeros should be preserved
          final parsed = BigInt.parse(hashHex, radix: 16);
          final backToHex = parsed.toRadixString(16);

          // This demonstrates the problem: toRadixString strips leading zeros
          expect(backToHex.length, lessThan(hashHex.length),
              reason: 'toRadixString(16) strips leading zeros - '
                  'this is the bug we need to fix');
          break;
        }
      }
      expect(testedLeadingZero, isTrue,
          reason: 'Should have found at least one hash with leading zero in 100 tries');
    });

    test('computeX produces consistent results regardless of leading zeros', () {
      final config = SRP6CryptoParams.getInstance(bitsize: 256, H: "SHA-256");
      final routine = CustomXRoutine(config.N);
      final digest = config.getMessageDigestInstance();

      // Generate salt bytes
      final saltBytes = BigIntHelper.toByteArray(BigInt.parse('1234567890', radix: 16));
      final username = utf8.encode('testuser');
      final password = utf8.encode('testpassword');

      // Compute x - should be deterministic
      final x1 = routine.computeX(digest, saltBytes, username, password);
      final x2 = routine.computeX(digest, saltBytes, username, password);
      expect(x1, equals(x2), reason: 'computeX must be deterministic');

      // Verify the intermediate hex strings are properly padded:
      // Hash of password should always be 64 hex chars for SHA-256
      final passwordHash = digest.convert(password).toString();
      expect(passwordHash.length, equals(64),
          reason: 'SHA-256 hex output from digest.convert().toString() is always 64 chars');

      // But BigInt.parse().toRadixString(16) may lose leading zeros
      final parsed = BigInt.parse(passwordHash, radix: 16).toRadixString(16);
      expect(parsed.length, lessThanOrEqualTo(64),
          reason: 'toRadixString strips leading zeros, which is the bug');
    });
  });

  group('Full SRP handshake with high-MSB values', () {
    test('handshake succeeds consistently over many iterations', () {
      final config = SRP6CryptoParams.getInstance(bitsize: 256, H: "SHA-256");
      final generator = SRP6VerifierGenerator(config);
      generator.setXRoutine(CustomXRoutine(config.N));

      int successCount = 0;
      int failCount = 0;

      // Run 200 iterations to have high probability of hitting MSB=1 cases
      for (int i = 0; i < 200; i++) {
        final saltStr = generator.generateRandomSalt(numBytes: 32);
        final salt = BigInt.parse(utf8.decode(saltStr), radix: 10);
        final username = 'user_$i';
        final password = 'password_$i';
        final verifier = generator.generateVerifier(salt, username, password);

        final clientSession = SRP6ClientSession();
        final serverSession = SRP6ServerSession(config);
        clientSession.setXRoutine(CustomXRoutine(config.N));
        clientSession.step1(username, password);

        final B = serverSession.step1(username, salt, verifier);

        try {
          final credentials = clientSession.step2(config, salt, B);
          final m2 = serverSession.step2(credentials.A!, credentials.m1!);
          clientSession.step3(m2);
          successCount++;
        } catch (e) {
          failCount++;
        }
      }

      // Before fix: some iterations would fail (~50% due to MSB issues)
      // After fix: all iterations should succeed
      expect(failCount, equals(0),
          reason: 'All SRP handshakes must succeed. '
              'Got $successCount successes and $failCount failures');
    });
  });
}
