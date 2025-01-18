import 'package:crypto/crypto.dart';

import 'illegal_argument_exception.dart';
import 'illegal_state_exception.dart';
import 'srp6_client_evidence_context.dart';
import 'srp6_crypto_params.dart';
import 'srp6_exception.dart';
import 'srp6_routines.dart';
import 'srp6_server_evidence_context.dart';
import 'srp6_session.dart';
import 'uroutine_context.dart';

enum SrpState { init, step1, step2 }

class SRP6ServerSession extends SRP6Session {
  bool noSuchUserIdentity = false;
  BigInt? v;
  BigInt? b;
  SrpState state;

  SRP6ServerSession(final SRP6CryptoParams config,
      {final int timeout = 0, this.state = SrpState.init}) {
    this.config = config;
    state = SrpState.init;
    updateLastActivityTime();
  }

  BigInt step1(final String userID, final BigInt s, final BigInt v) {
    // Check arguments

    if (userID.trim().isEmpty) {
      throw IllegalArgumentException(
          "The user identity 'I' must not be null or empty");
    }

    this.userID = userID;
    this.s = s;
    this.v = v;

    if (state != SrpState.init) {
      throw IllegalStateException(
          "State violation: Session must be in INIT state");
    }

    Hash digest = config!.getMessageDigestInstance();
    k = SRP6Routines.computeK(digest, config!.N, config!.g);
    b = SRP6Routines.generatePrivateValue(config!.N, random);
    B = SRP6Routines.computePublicServerValue(config!.N, config!.g, k!, v, b!);
    state = SrpState.step1;

    updateLastActivityTime();

    return B!;
  }

  BigInt mockStep1(final String userID, final BigInt s, final BigInt v) {
    noSuchUserIdentity = true;

    return step1(userID, s, v);
  }

  BigInt step2(final BigInt A, final BigInt m1) {
// Check arguments

    this.A = A;
    this.m1 = m1;

    if (state != SrpState.step1) {
      throw IllegalStateException(
          "State violation: Session must be in STEP_1 state");
    }

    if (hasTimedOut()) {
      throw SRP6Exception("Session timeout", CauseType.timeout);
    }

    if (!SRP6Routines.isValidPublicValue(config!.N, A)) {
      throw SRP6Exception(
          "Bad client public value 'A'", CauseType.badPublicValue);
    }

    if (noSuchUserIdentity) {
      throw SRP6Exception("Bad client credentials", CauseType.badCredentials);
    }

    Hash digest = config!.getMessageDigestInstance();

    if (hashedKeysRoutine != null) {
      URoutineContext hashedKeysContext = URoutineContext(A, B!);
      u = hashedKeysRoutine!.computeU(config!, hashedKeysContext);
    } else {
      u = SRP6Routines.computeU(digest, config!.N, A, B!);
    }

    S = SRP6Routines.computeServerSessionKey(config!.N, v!, u!, A, b!);
    BigInt computedM1;

    if (clientEvidenceRoutine != null) {
      SRP6ClientEvidenceContext ctx =
          SRP6ClientEvidenceContext(userID!, s!, A, B!, S!);
      computedM1 = clientEvidenceRoutine!.computeClientEvidence(config!, ctx);
    } else {
      computedM1 = SRP6Routines.computeClientEvidence(digest, A, B!, S!);
    }

    if (computedM1 != m1) {
      throw SRP6Exception("Bad client credentials", CauseType.badCredentials);
    }

    state = SrpState.step2;

    if (serverEvidenceRoutine != null) {
      SRP6ServerEvidenceContext ctx = SRP6ServerEvidenceContext(A, m1, S!);

      m2 = serverEvidenceRoutine!.computeServerEvidence(config!, ctx);
    } else {
      m2 = SRP6Routines.computeServerEvidence(digest, A, m1, S!);
    }

    updateLastActivityTime();

    return m2!;
  }

  SrpState getState() {
    return state;
  }
}
