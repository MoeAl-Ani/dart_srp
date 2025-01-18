import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

import 'bigint_helper.dart';

class SRP6Routines {

  static BigInt computeK(final Hash digest,
      final BigInt N,
      final BigInt g) {
    return hashPaddedPair(digest, N, N, g);
  }

  static List<int> generateRandomSalt(final int numBytes) {
    Random random = Random.secure();
    return utf8.encode(random.nextInt(numBytes).toRadixString(10));
  }

  static BigInt computeX(final Hash digest,
      final List<int> salt,
      final List<int> password) {
    List<int> output = digest.convert(password).bytes;
    List<int> saltoutputConcatinated = BigIntHelper.concatByteArray(salt, output);
    String hashedX = digest.convert(saltoutputConcatinated).toString();
    return BigInt.parse(hashedX, radix: 16);
  }

  static BigInt computeVerifier(final BigInt N,
      final BigInt g,
      final BigInt x) {
    return g.modPow(x, N);
  }

  static BigInt generatePrivateValue(final BigInt N,
      final Random random) {
    BigInt r = BigIntHelper.createRandomBigInt();
    if (r.isNegative) {
      r = BigIntHelper.toPositiveBigInt(r);
    }
    return r;
  }

  static BigInt computePublicClientValue(final BigInt N,
      final BigInt g,
      final BigInt a) {
    return g.modPow(a, N);
  }

  static BigInt computePublicServerValue(final BigInt N,
      final BigInt g,
      final BigInt k,
      final BigInt v,
      final BigInt b) {
    return g.modPow(b, N) + (v * (k)).remainder(N);
  }

  static bool isValidPublicValue(final BigInt N,
      final BigInt value) {
    // check that value % N != 0
    return value.remainder(N) != (BigInt.zero);
  }

  static BigInt computeU(final Hash digest,
      final BigInt N,
      final BigInt A,
      final BigInt B) {
    return hashPaddedPair(digest, N, A, B);
  }

  static BigInt computeClientSessionKey(final BigInt N,
      final BigInt g,
      final BigInt k,
      final BigInt x,
      final BigInt u,
      final BigInt a,
      final BigInt B) {
    final BigInt exp = (u * x) + a;
    final BigInt tmp = g.modPow(x, N) * k;
    BigInt sessKey = (B - (tmp)).modPow(exp, N);
    if (sessKey.isNegative) {
      sessKey = BigIntHelper.toPositiveBigInt(sessKey);
      if(sessKey.isNegative) {}
    }
    return sessKey;
  }

  static BigInt computeServerSessionKey(final BigInt N,
      final BigInt v,
      final BigInt u,
      final BigInt A,
      final BigInt b) {
    return (v.modPow(u, N)*(A)).modPow(b, N);
  }

  static BigInt computeClientEvidence(final Hash digest,
      final BigInt A,
      final BigInt B,
      final BigInt S) {
    List<int> e1 = BigIntHelper.toByteArray(A);
    List<int> e2 = BigIntHelper.toByteArray(B);
    List<int> e3 = BigIntHelper.toByteArray(S);
    List<int> res1 = BigIntHelper.concatByteArray(e1,e2);
    List<int> finalRes = BigIntHelper.concatByteArray(res1, e3);
    var digestedValue = digest.convert(finalRes).toString();
    return BigInt.parse(digestedValue, radix: 16);

  }

  static BigInt computeServerEvidence(final Hash digest,
      final BigInt A, final BigInt m1, final BigInt S) {
    List<int> e1 = BigIntHelper.toByteArray(A);
    List<int> e2 = BigIntHelper.toByteArray(m1);
    List<int> e3 = BigIntHelper.toByteArray(S);
    List<int> finalRes = BigIntHelper.concatByteArray(BigIntHelper.concatByteArray(e1, e2), e3);
    var digestedValue = digest.convert(finalRes).toString();
    return BigInt.parse(digestedValue, radix: 16);
  }

  static BigInt hashPaddedPair(final Hash digest,
      final BigInt N,
      final BigInt n1,
      final BigInt n2) {
    final int padLength = (N.bitLength + 7) ~/ 8;

    List<int> n1Bytes = BigIntHelper.getPadded(n1, padLength);
    List<int> n2Bytes = BigIntHelper.getPadded(n2, padLength);
    List<int> finalResult = BigIntHelper.concatByteArray(n1Bytes, n2Bytes);

    String digestedHash = digest.convert(finalResult).toString();

    return BigInt.parse(digestedHash, radix: 16);
  }


  SRP6Routines() {
    // empty
  }
}
