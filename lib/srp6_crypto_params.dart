
import 'package:crypto/crypto.dart';

import 'illegal_argument_exception.dart';

class SRP6CryptoParams {
  static final BigInt n256 = BigInt.parse(
      "125617018995153554710546479714086468244499594888726646874671447258204721048803",
      radix: 10);
  static final BigInt n512 = BigInt.parse(
      "11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603",
      radix: 10);
  static final BigInt n768 = BigInt.parse(
      "1087179135105457859072065649059069760280540086975817629066444682366896187793570736574549981488868217843627094867924800342887096064844227836735667168319981288765377499806385489913341488724152562880918438701129530606139552645689583147",
      radix: 10);
  static final BigInt n1024 = BigInt.parse(
      "167609434410335061345139523764350090260135525329813904557420930309800865859473551531551523800013916573891864789934747039010546328480848979516637673776605610374669426214776197828492691384519453218253702788022233205683635831626913357154941914129985489522629902540768368409482248290641036967659389658897350067939",
      radix: 10);
  static final BigInt n1536 = BigInt.parse(
      "1486998185923128292816507353619409521152457662596380074614818966810244974827752411420380336514078832314731499938313197533147998565301020797040787428051479639316928015998415709101293902971072960487527411068082311763171549170528008620813391411445907584912865222076100726050255271567749213905330659264908657221124284665444825474741087704974475795505492821585749417639344967192301749033325359286273431675492866492416941152646940908101472416714421046022696100064262587",
      radix: 10);
  static final BigInt n2048 = BigInt.parse(
      "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
      radix: 10);
  static final BigInt gCommon = BigInt.from(2);

  BigInt N;
  BigInt g;
  String H;

  static SRP6CryptoParams getInstance({final int bitsize = 512, final String H="SHA-1"}) {

    if (H.isEmpty) {
      throw IllegalArgumentException("Undefined hash algorithm 'H'");
    }

    if (bitsize == 256) {
      return SRP6CryptoParams(n256, gCommon, H);
    } else if (bitsize == 512) {
      return SRP6CryptoParams(n512, gCommon, H);
    } else if (bitsize == 768) {
      return SRP6CryptoParams(n768, gCommon, H);
    } else if (bitsize == 1024) {
      return SRP6CryptoParams(n1024, gCommon, H);
    } else if (bitsize == 1536) {
      return SRP6CryptoParams(n1536, gCommon, H);
    } else if (bitsize == 2048) {
      return SRP6CryptoParams(n2048, gCommon, H);
    } else {
      return throw UnsupportedError("no valid alg found");
    }
  }


  /// for now yes is supported
  /// // TODO check that hash is supported.
  static bool isSupportedHashAlgorithm(final String H) {
      return true;
  }

  SRP6CryptoParams(this.N, this.g, this.H) {
    N = N;

    if (g == BigInt.one) {
      throw IllegalArgumentException(
          "The generator parameter 'g' must not be 1");
    }

    if (g == (N - BigInt.one)) {
      throw IllegalArgumentException(
          "The generator parameter 'g' must not equal N - 1");
    }

    if (g == BigInt.zero) {
      throw IllegalArgumentException(
          "The generator parameter 'g' must not be 0");
    }

    g = g;

    if (H.isEmpty) {
      throw IllegalArgumentException("Undefined hash algorithm 'H'");
    }

    if (!isSupportedHashAlgorithm(H)) {
      throw IllegalArgumentException("Unsupported hash algorithm 'H': $H");
    }

    H = H;
  }

  /// now it is hard coded SHA-256
  Hash getMessageDigestInstance() {

    try {
      if (H.contains("SHA-256")) {
        return sha256;
      } else {
        throw UnimplementedError("fornow");
      }
    } catch (e) {
    rethrow;
    }
  }
}
