import 'package:crypto/crypto.dart';
abstract class XRoutine {
  BigInt computeX(final Hash digest,
final List<int> salt,
final List<int> username,
final List<int> password);
}