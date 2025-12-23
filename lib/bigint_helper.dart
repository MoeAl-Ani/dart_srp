import 'dart:math';
import 'dart:typed_data';

class BigIntHelper {

  /// decode byte array to BigInt
  static BigInt decodeBigInt(Uint8List bytes, {Endian endian = Endian.big}) {
    BigInt result = BigInt.from(0);
    for (int i = 0; i < bytes.length; i++) {
      result += BigInt.from(
          bytes[endian == Endian.little ? i : bytes.length - i - 1]) <<
          (8 * i);
    }
    return result;
  }

  static Uint8List encodeBigInt(BigInt number, {Endian endian = Endian.little}) {

    int size = (((number.bitLength) / 8) + 1).toInt();
    var result = Uint8List(size);
    for (int i = 0; i < size; i++) {
      result[endian != Endian.little ? i : size - i - 1] =
          (number & BigInt.from(0xff)).toInt();
      number = number >> 8;
    }
    return result;
  }

  static List<int> bigIntegerToUnsignedByteArray(final BigInt value) {
    List<int> bytes = toByteArray(value).toList();
    if (bytes[0] == 0) {
      List<int> tmp = List.filled(bytes.length -1, 0);
     return arrayCopy(bytes, 1, tmp, 0, tmp.length);
    }
    return bytes;
  }

  /// convert BigInt to byte array.
  static Uint8List toByteArray(BigInt number) {
    int size = (number.bitLength + 7) >> 3;
    var result = Uint8List(size);
    for (int i = 0; i < size; i++) {
      result[size - i - 1] = (number & BigInt.from(0xff)).toInt();
      number = number >> 8;
    }
    return result;
  }

  /// convert BigInt to hex String.
  static String toHex(final BigInt bigint) {
    return bigint.toRadixString(16);
  }

  /// convert hex String to BigInt
  static BigInt fromHex(final String hex) {
    try {
      return BigInt.parse(hex, radix: 16);
    } catch (e) {
      print (e);
      rethrow;
    }
  }

  /// Pads a big integer with leading zeros up to the specified length.
  ///
  /// @param n      The big integer to pad. Must not be {@code null}.
  /// @param length The required length of the padded big integer as a
  ///               byte array.
  ///
  /// @return The padded big integer as a byte array.
  static List<int> getPadded(BigInt value, int length) {
    List<int> bs = bigIntegerToUnsignedByteArray(value);
    if (bs.length < length) {
      List<int> tmp = List.filled(length, 0);
      arrayCopy(bs, 0, tmp, length - bs.length, bs.length);
      bs = tmp;
    }
    return bs;
  }

  /// standard array copy
  static List<int> arrayCopy(bytes, srcOffset, result, destOffset, bytesLength) {
    for (var i = srcOffset; i < bytesLength; i++) {
      result[destOffset + i] = bytes[i];
    }
    return result;
  }

  /// concatenate byte arrays.
  static List<int> concatByteArray(List<int> arr1, List<int> arr2) {
    List<int> result = List.filled(arr1.length + arr2.length, 0);
    for (int i = 0; i< arr1.length; i++) {
      result[i] = arr1[i];
    }
    int count = 0;
    for (int i = arr1.length; i < result.length; i++) {
      result[i] = arr2[count];
      count++;
    }
    return result;
  }

  /// Returns a random big integer.
  static BigInt createRandomBigInt({int numBytes = 32}) {
    final random = Random.secure();
    final bytes = Uint8List(numBytes);
    for (var i = 0; i < numBytes; i++) {
      bytes[i] = random.nextInt(256);
    }
    return BigIntHelper.decodeBigInt(bytes);
  }

  /// convert a signed BigInt to Unsigned BigInt
  static BigInt toPositiveBigInt(BigInt value) {
    return decodeBigInt(Uint8List.fromList(bigIntegerToUnsignedByteArray(value)));
  }
}