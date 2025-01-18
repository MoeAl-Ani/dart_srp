import 'srp6_client_evidence_context.dart';
import 'srp6_crypto_params.dart';

abstract class ClientEvidenceRoutine {
  BigInt computeClientEvidence(
      SRP6CryptoParams cryptoParams, SRP6ClientEvidenceContext ctx);
}
