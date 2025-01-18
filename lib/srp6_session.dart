import 'dart:math';
import 'dart:typed_data';

import 'URoutine.dart';
import 'bigint_helper.dart';
import 'client_evidence_routine.dart';
import 'illegal_argument_exception.dart';
import 'server_evidence_routine.dart';
import 'srp6_crypto_params.dart';

abstract class SRP6Session {

  SRP6CryptoParams? config;
  final Random random = Random();
  int? timeout;
  int? lastActivity;
  String? userID;
  BigInt? s;
  BigInt? A;
  BigInt? B;
  BigInt? u;
  BigInt? k;
  BigInt? S;
  BigInt? m1;
  BigInt? m2;
  ClientEvidenceRoutine? clientEvidenceRoutine;
  ServerEvidenceRoutine? serverEvidenceRoutine;
  URoutine? hashedKeysRoutine;
  Map<String, dynamic>? attributes;

  SRP6Session({int this.timeout = 0}) {
    if (timeout == null || timeout! < 0) {
      throw IllegalArgumentException("The timeout must be zero (no timeout) or greater");
    }
  }

  void updateLastActivityTime() {
    lastActivity = DateTime.now().millisecondsSinceEpoch;
  }

  int getLastActivityTime() {
    return lastActivity ?? 0;
  }

  bool hasTimedOut() {

    if (timeout == 0) {
      return false;
    }

    final int now = DateTime.now().millisecondsSinceEpoch;
    return now > lastActivity! + (timeout! * 1000);
  }

  Future<SRP6CryptoParams> getCryptoParams() async {
    return config!;
  }

  String getUserID() {
    return userID!;
  }

  int getTimeout() {
    return timeout!;
  }

  void setClientEvidenceRoutine(final ClientEvidenceRoutine routine) {
    clientEvidenceRoutine = routine;
  }

  ClientEvidenceRoutine getClientEvidenceRoutine() {
    return clientEvidenceRoutine!;
  }

  void setServerEvidenceRoutine(final ServerEvidenceRoutine routine) {

    serverEvidenceRoutine = routine;
  }

  ServerEvidenceRoutine getServerEvidenceRoutine() {

    return serverEvidenceRoutine!;
  }

  URoutine getHashedKeysRoutine() {

    return hashedKeysRoutine!;
  }

  void setHashedKeysRoutine(final URoutine hashedKeysRoutine) {

    this.hashedKeysRoutine = hashedKeysRoutine;
  }

  BigInt getSalt() {
    return s!;
  }

  BigInt getPublicClientValue() {
    return A!;
  }

  BigInt getPublicServerValue() {
    return B!;
  }

  BigInt getClientEvidenceMessage() {
    return m1!;
  }

  BigInt getServerEvidenceMessage() {
    return m2!;
  }

  BigInt getSessionKey(final bool doHash) {

    if (S == null) {
      return BigInt.from(0);
    }

    if (doHash) {
      var convert = config?.getMessageDigestInstance().convert(BigIntHelper.toByteArray(S!));
      var bytes = convert!.bytes;
      return BigInt.from(BigIntHelper.decodeBigInt(Uint8List.fromList(bytes)).toInt());
    }
    else {
      return S!;
    }
  }

  void setAttribute(final String key, final Object value) {
    attributes ??= <String, dynamic>{};
    attributes?[key] = value;
  }

  dynamic getAttribute(final String key) {

    if (attributes == null) {
      return null;
    }

    return attributes?[key];
  }
}
