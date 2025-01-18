
import 'URoutine.dart';
import 'bigInt_helper.dart';
import 'hex_hashed_routines.dart';
import 'srp6_crypto_params.dart';
import 'uroutine_context.dart';

class HexHashedURoutine extends URoutine {

  @override
  BigInt computeU(SRP6CryptoParams cryptoParams, URoutineContext ctx) {
    return HexHashedRoutines.hashURoutine(
        cryptoParams.getMessageDigestInstance(),
        BigIntHelper.toHex(ctx.A),
        BigIntHelper.toHex(ctx.B));
  }

}