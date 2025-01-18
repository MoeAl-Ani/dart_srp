import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'bigInt_helper.dart';
import 'illegal_argument_exception.dart';
import 'illegal_state_exception.dart';
import 'srp6_client_credentials.dart';
import 'srp6_client_evidence_context.dart';
import 'srp6_crypto_params.dart';
import 'srp6_exception.dart';
import 'srp6_routines.dart';
import 'srp6_server_evidence_context.dart';
import 'srp6_session.dart';
import 'uroutine_context.dart';
import 'xroutine.dart';

enum SrpState { init, step1, step2, step3 }

class SRP6ClientSession extends SRP6Session {
  String? password;
  BigInt? x;
  BigInt? a;
  SrpState state;
  XRoutine? xRoutine;

  SRP6ClientSession({int timeout = 0, this.state = SrpState.init}) : super() {
    updateLastActivityTime();
  }

  void setXRoutine(final XRoutine routine) {
    xRoutine = routine;
  }

  XRoutine? getXRoutine() {
    return xRoutine;
  }

  void step1(final String? userID, final String? password) {
    if (userID == null || userID.trim().isEmpty) {
      throw IllegalArgumentException(
          "The user identity 'I' must not be null or empty");
    }

    this.userID = userID;

    if (password == null) {
      throw IllegalArgumentException(
          "The user password 'P' must not be null");
    }

    this.password = password;

    // Check current state
    if (state != SrpState.init) {
      throw IllegalStateException(
          "State violation: Session must be in INIT state");
    }

    state = SrpState.step1;

    updateLastActivityTime();
  }

  SRP6ClientCredentials step2(
      final SRP6CryptoParams? config, final BigInt? s, final BigInt? B) {
    if (config == null) {
      throw IllegalArgumentException(
          "The SRP-6a crypto parameters must not be null");
    }

    this.config = config;

    Hash digest = config.getMessageDigestInstance();

    if (s == null) {
      throw IllegalArgumentException("The salt 's' must not be null");
    }

    this.s = s;

    if (B == null) {
      throw IllegalArgumentException(
          "The server value 'B' must not be null");
    }

    this.B = B;

    if (state != SrpState.step1) {
      throw IllegalStateException(
          "State violation: Session must be in STEP_1 state");
    }

    if (hasTimedOut()) {
      throw SRP6Exception("Session timeout", CauseType.timeout);
    }

    if (!SRP6Routines.isValidPublicValue(config.N, B)) {
      throw SRP6Exception("Bad server value 'B'", CauseType.badPublicValue);
    }

    if (xRoutine != null) {
      x = xRoutine?.computeX(
          config.getMessageDigestInstance(),
          BigIntHelper.toByteArray(s),
          utf8.encode(userID!),
          utf8.encode(password ?? ""));
    } else {
      x = SRP6Routines.computeX(
          digest, BigIntHelper.toByteArray(s), utf8.encode(password ?? ""));
    }

    a = SRP6Routines.generatePrivateValue(config.N, random);
    A = SRP6Routines.computePublicClientValue(config.N, config.g, a!);
    k = SRP6Routines.computeK(digest, config.N, config.g);

    if (hashedKeysRoutine != null) {
      URoutineContext hashedKeysContext = URoutineContext(A!, B);
      u = hashedKeysRoutine!.computeU(config, hashedKeysContext);
    } else {
      u = SRP6Routines.computeU(digest, config.N, A!, B);
    }

    S = SRP6Routines.computeClientSessionKey(config.N, config.g, k!, x!, u!, a!, B);

    if (clientEvidenceRoutine != null) {
      SRP6ClientEvidenceContext ctx =
          SRP6ClientEvidenceContext(userID!, s, A!, B, S!);
      m1 = clientEvidenceRoutine!.computeClientEvidence(config, ctx);
    } else {
      m1 = SRP6Routines.computeClientEvidence(digest, A!, B, S!);
    }

    state = SrpState.step2;
    updateLastActivityTime();

    return SRP6ClientCredentials(A, m1);
  }

  void step3(final BigInt m2) {
    this.m2 = m2;

    if (state != SrpState.step2) {
      throw IllegalStateException(
          "State violation: Session must be in STEP_2 state");
    }

    if (hasTimedOut()) {
      throw SRP6Exception("Session timeout", CauseType.timeout);
    }

    BigInt computedM2;

    if (serverEvidenceRoutine != null) {
      SRP6ServerEvidenceContext ctx = SRP6ServerEvidenceContext(A!, m1!, S!);
      computedM2 = serverEvidenceRoutine!.computeServerEvidence(config!, ctx);
    } else {
      Hash digest = config!.getMessageDigestInstance();
      computedM2 = SRP6Routines.computeServerEvidence(digest, A!, m1!, S!);
    }

    if (computedM2 != m2) {
      throw SRP6Exception("Bad server credentials", CauseType.badCredentials);
    }

    state = SrpState.step3;

    updateLastActivityTime();
  }

  SrpState getState() {
    return state;
  }
}
