import 'bigint_helper.dart';
import 'client_evidence_routine.dart';
import 'hex_hashed_routines.dart';
import 'srp6_client_evidence_context.dart';
import 'srp6_crypto_params.dart';

class HexHashedClientEvidenceRoutine extends ClientEvidenceRoutine {

  @override
  BigInt computeClientEvidence(
      SRP6CryptoParams cryptoParams, SRP6ClientEvidenceContext ctx) {
    return HexHashedRoutines.hashClientEvidence(
        cryptoParams.getMessageDigestInstance(),
        BigIntHelper.toHex(ctx.A),
        BigIntHelper.toHex(ctx.B),
        BigIntHelper.toHex(ctx.S));
  }

}
