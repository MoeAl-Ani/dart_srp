## 1.1.0

- Fixed Java/Nimbus compatibility: evidence computation (M1/M2) now uses signed byte encoding matching Java's BigInteger.toByteArray().
- Fixed inverted endianness logic in BigIntHelper.encodeBigInt and aligned default to Endian.big.
- Fixed hex string padding in CustomXRoutine to preserve leading zeros.
- Renamed integration test to snake_case and migrated to the test package.

## 1.0.0

- Initial SRP version.

## 1.0.1

- Followed dart naming conventions.

## 1.0.2

- Updated homepage.

## 1.0.3

- Updated license

## 1.0.4

- Fixed BigInt import

## 1.0.5

- Fixed undefined imports

## 1.0.6

- Better salt generation impl.
