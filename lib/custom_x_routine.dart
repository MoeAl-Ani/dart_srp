import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'bigInt_helper.dart';
import 'xroutine.dart';

class CustomXRoutine extends XRoutine {
  BigInt N;

  CustomXRoutine(this.N);

  @override
  BigInt computeX(Hash digest, List<int> salt, List<int> username, List<int> password) {
    List<int> c1 = List.empty(growable: true);
    c1.addAll(username);
    c1.addAll(utf8.encode(":"));
    c1.addAll(password);
    var h1 = BigInt.parse(digest.convert(c1).toString(), radix: 16).toRadixString(16);
    var saltHexed = BigIntHelper.toPositiveBigInt(BigInt.parse(BigIntHelper.decodeBigInt(Uint8List.fromList(salt)).toString(), radix: 10)).toRadixString(16);
    var concat = (saltHexed + h1).toUpperCase();
    var bigIntFromHashValue = BigInt.parse(digest.convert(utf8.encode(concat)).toString(), radix: 16);
    var remainder = bigIntFromHashValue.remainder(N);
    return remainder;
  }
}

Uint8List convertStringToUint8List(String str) {
  final List<int> codeUnits = utf8.encode(str);
  final Uint8List unit8List = Uint8List.fromList(codeUnits);

  return unit8List;
}