
import 'illegal_argument_exception.dart';

class SRP6ClientCredentials {

  BigInt? A;
  BigInt? m1;

  SRP6ClientCredentials(this.A, this.m1) {
    if (A == null) {
      throw IllegalArgumentException("The public client value 'A' must not be null");
    }

    if (m1 == null) {
      throw IllegalArgumentException("The client evidence message 'M1' must not be null");
    }
  }
}