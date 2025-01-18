import 'dart:convert';

import 'package:crypto/crypto.dart';

class HexHashedRoutines {

  static BigInt hashClientEvidence(final Hash digest, String A, String B, String S) {
  String concatenated = A + B + S;
  List<int> byte = utf8.encode(concatenated);
  List<int> digested = digest.convert(byte).bytes;
  String decoded = utf8.decode(digested);
  return BigInt.parse(decoded, radix: 16);
  }

  static BigInt hashServerEvidence(
      final Hash digest, String A, String m1, String S) {
    String concatenated = A + m1 + S;
    List<int> byte = utf8.encode(concatenated);
    List<int> digested = digest.convert(byte).bytes;
    String decoded = utf8.decode(digested);
    return BigInt.parse(decoded, radix: 16);
  }

  static BigInt hashURoutine(final Hash digest, String A, String B) {
    String concatenated = A + B;
    List<int> byte = utf8.encode(concatenated);
    List<int> digested = digest.convert(byte).bytes;
    String decoded = utf8.decode(digested);
    return BigInt.parse(decoded, radix: 16);
  }
}