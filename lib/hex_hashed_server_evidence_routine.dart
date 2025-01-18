import 'bigint_helper.dart';
import 'hex_hashed_routines.dart';
import 'server_evidence_routine.dart';
import 'srp6_crypto_params.dart';
import 'srp6_server_evidence_context.dart';

class HexHashedServerEvidenceRoutine extends ServerEvidenceRoutine {

  @override
  BigInt computeServerEvidence(
      SRP6CryptoParams cryptoParams, SRP6ServerEvidenceContext ctx) {
    return HexHashedRoutines.hashServerEvidence(
        cryptoParams.getMessageDigestInstance(),
        BigIntHelper.toHex(ctx.A),
        BigIntHelper.toHex(ctx.m1),
        BigIntHelper.toHex(ctx.S));
  }
}
