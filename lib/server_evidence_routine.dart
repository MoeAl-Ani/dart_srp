import 'srp6_crypto_params.dart';
import 'srp6_server_evidence_context.dart';

abstract class ServerEvidenceRoutine {

  BigInt computeServerEvidence(SRP6CryptoParams cryptoParams,
      final SRP6ServerEvidenceContext ctx);
}