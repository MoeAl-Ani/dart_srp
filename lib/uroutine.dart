import 'srp6_crypto_params.dart';
import 'uroutine_context.dart';

abstract class URoutine {

  BigInt computeU(final SRP6CryptoParams cryptoParams, final URoutineContext ctx);
}