/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.ss3t.javacard.gpg;

import net.ss3t.javacard.CardInterfaceBuilder;
import net.ss3t.javacard.HexString;
import net.ss3t.javacard.TLVDer;

import org.junit.Test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import static net.ss3t.javacard.CardUtils.assertSW;
import static net.ss3t.javacard.CardUtils.assertSWData;
import static net.ss3t.javacard.CardUtils.assertSWOnly;
import static net.ss3t.javacard.HexString.bytesToHex;
import static net.ss3t.javacard.HexString.mergeByteArrays;
import static net.ss3t.javacard.HexString.toByteArray;
import static net.ss3t.javacard.TLVDer.createTagLength;
import static net.ss3t.javacard.gpg.DataObject.SIGNATURE_COUNTER;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 */
public abstract class GpgCryptoTest extends GpgTest {

  public GpgCryptoTest(CardInterfaceBuilder builder) {
    super(builder);
  }

  @Test
  public void Random() throws CardException {
    ResponseAPDU response1 = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_CHALLENGE, 0, 0, 16));
    ResponseAPDU response2 = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_CHALLENGE, 0, 0, 16));
    assertEquals(16, response1.getData().length);
    assertEquals(16, response2.getData().length);
    assertFalse(Arrays.equals(response1.getData(), response2.getData()));
    response1 = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_CHALLENGE, 0, 0, 256));
    assertEquals(256, response1.getData().length);
  }

  private byte[] trimmedBigInteger(BigInteger n) {
    // Java can add a leading zero to make the number positive.
    byte[] t = n.toByteArray();
    if (t[0] == 0) {
      return Arrays.copyOfRange(t, 1, t.length);
    }
    return t;
  }

  /**
   * Compute the modulus and public exponent from the private CRT key parts and TLV encode them for
   * the card.
   *
   * @param keyType should be 0xB600 for the signature key, 0xB800 for the confidentiality key and
   *                0xA400 for the authentication key.
   * @param p       the first prime.
   * @param q       the second prime.
   * @return the TLV encoded private key.
   */
  private byte[] encodeCRTKey(int keyType, String p, String q, String dp1, String dq1, String pq) {
    BigInteger b_p = new BigInteger(1, toByteArray(p));
    BigInteger b_q = new BigInteger(1, toByteArray(q));
    BigInteger b_dp1 = new BigInteger(1, toByteArray(dp1));

    BigInteger e = b_dp1.modInverse(b_p.subtract(BigInteger.ONE));
    BigInteger n = b_p.multiply(b_q);
    byte[] modulus = trimmedBigInteger(n);
    byte[] publicExponent = trimmedBigInteger(e);
    byte[] tag5F48 = TLVDer.createTLVDER(
        0x5F48, mergeByteArrays(publicExponent, toByteArray(p + q + pq + dp1 + dq1), modulus));
    byte[] tag7F48 = TLVDer.createTLVDER(
        0x7F48,
        HexString.mergeByteArrays(createTagLength(0x91, publicExponent.length),
                                  createTagLength(0x92, toByteArray(p).length),
                                  createTagLength(0x93, toByteArray(q).length),
                                  createTagLength(0x94, toByteArray(pq).length),
                                  createTagLength(0x95, toByteArray(dp1).length),
                                  createTagLength(0x96, toByteArray(dq1).length),
                                  createTagLength(0x97, modulus.length)));
    return TLVDer.createTLVDER(0x4D, HexString.mergeByteArrays(
        createTagLength(keyType, 0), tag7F48, tag5F48));
  }

  private byte[] encodePublicKey(String p, String q, String dp1) {
    BigInteger b_p = new BigInteger(1, toByteArray(p));
    BigInteger b_q = new BigInteger(1, toByteArray(q));
    BigInteger b_dp1 = new BigInteger(1, toByteArray(dp1));

    BigInteger e = b_dp1.modInverse(b_p.subtract(BigInteger.ONE));
    BigInteger n = b_p.multiply(b_q);
    byte[] modulus = trimmedBigInteger(n);
    byte[] publicExponent = trimmedBigInteger(e);

    return TLVDer.createTLVDER(
        0x7F49,
        mergeByteArrays(TLVDer.createTLVDER(0x82, publicExponent),
                        TLVDer.createTLVDER(0x81, modulus)));
  }

  final String signatureP =
      "f4 4f 5e 42 46 39 1f 48 2b 2f 52 96 e3 60 2e b3" +
      "4a a1 36 42 77 10 f7 c0 41 6d 40 3f d6 9d 4b 29" +
      "13 0c fe be f3 4e 88 5a bd b1 a8 a0 a5 f0 e9 b5" +
      "c3 3e 1f c3 bf c2 85 b1 ae 17 e4 0c c6 7a 19 13" +
      "dd 56 37 19 81 5e ba f8 51 4c 2a 7a a0 01 8e 63" +
      "b6 c6 31 dc 31 5a 46 23 57 16 42 3d 11 ff 58 03" +
      "4e 61 06 45 70 36 06 91 9f 5c 7c e2 66 0c d1 48" +
      "bd 9e fc 12 3d 9c 54 b6 70 55 90 d0 06 cf cf 3f";
  final String signatureQ =
      "e9 d4 98 41 e0 e0 a6 ad 0d 51 78 57 13 3e 36 dc" +
      "72 c1 bd d9 0f 91 74 b5 2e 26 57 0f 37 36 40 f1" +
      "c1 85 e7 ea 8e 2e d7 f1 e4 eb b9 51 f7 0a 58 02" +
      "36 33 b0 09 7a ec 67 c6 dc b8 00 fc 1a 67 f9 bb" +
      "05 63 61 0f 08 eb c8 74 6a d1 29 77 21 36 eb 1d" +
      "da f4 64 36 45 0d 31 83 32 a8 49 82 fe 5d 28 db" +
      "e5 b3 e9 12 40 7c 3e 0e 03 10 0d 87 d4 36 ee 40" +
      "9e ec 1c f8 5e 80 ab a0 79 b2 e6 10 6b 97 bc ed";
  final String signatureDP1 =
      "ed 10 2a cd b2 68 71 53 4d 1c 41 4e ca d9 a4 d7" +
      "32 fe 95 b1 0e ea 37 0d a6 2f 05 de 2c 39 3b 1a" +
      "63 33 03 ea 74 1b 6b 32 69 c9 7f 70 4b 35 27 02" +
      "c9 ae 79 92 2f 7b e8 d1 0d b6 7f 02 6a 81 45 de" +
      "41 b3 0c 0a 42 bf 92 3b ac 5f 75 04 c2 48 60 4b" +
      "9f aa 57 ed 6b 32 46 c6 ba 15 8e 36 c6 44 f8 b9" +
      "54 8f cf 4f 07 e0 54 a5 6f 76 86 74 05 44 40 bc" +
      "0d cb bc 9b 52 8f 64 a0 17 06 e0 5b 0b 91 10 6f";
  final String signatureDQ1 =
      "68 27 92 4a 85 e8 8b 55 ba 00 f8 21 91 28 bd 37" +
      "24 c6 b7 d1 df e5 62 9e f1 97 92 5f ec af f5 ed" +
      "b9 cd f3 a7 be fd 8e a2 e8 dd 37 07 13 8b 3f f8" +
      "7c 3c 39 c5 7f 43 9e 56 2e 2a a8 05 a3 9d 7c d7" +
      "99 66 d2 ec e7 84 5f 1d bc 16 be e9 99 99 e4 d0" +
      "bf 9e ec a4 5f cd a8 a8 50 00 35 fe 6b 5f 03 bc" +
      "2f 6d 1b fc 4d 4d 0a 37 23 96 1a f0 cd ce 4a 01" +
      "ee c8 2d 7f 54 58 ec 19 e7 1b 90 ee ef 7d ff 61";
  final String signaturePQ =
      "57 b7 38 88 d1 83 a9 9a 63 07 42 22 77 55 1a 3d" +
      "9e 18 ad f0 6a 91 e8 b5 5c ef fe f9 07 7c 84 96" +
      "94 8e cb 3b 16 b7 81 55 cb 2a 3a 57 c1 19 d3 79" +
      "95 1c 01 0a a6 35 ed cf 62 d8 4c 5a 12 2a 8d 67" +
      "ab 5f a9 e5 a4 a8 77 2a 1e 94 3b af c7 0a e3 a4" +
      "c1 f0 f3 a4 dd ff ae fd 18 92 c8 cb 33 bb 0d 0b" +
      "95 90 e9 63 a6 91 10 fb 34 db 7b 90 6f c4 ba 28" +
      "36 99 5a ac 7e 52 74 90 ac 95 2a 02 26 8a 4f 18";

  // Example 15.5 from pkcs1v15sign-vectors.txt
  final String signatureTestData =
      "bd a3 a1 c7 90 59 ea e5 98 30 8d 3d f6 09";

  final String expectedSignature =
      "a1 56 17 6c b9 67 77 c7 fb 96 10 5d bd 91 3b c4 "
      + "f7 40 54 f6 80 7c 60 08 a1 a9 56 ea 92 c1 f8 1c "
      + "b8 97 dc 4b 92 ef 9f 4e 40 66 8d c7 c5 56 90 1a "
      + "cb 6c f2 69 fe 61 5b 0f b7 2b 30 a5 13 38 69 23 "
      + "14 b0 e5 87 8a 88 c2 c7 77 4b d1 69 39 b5 ab d8 "
      + "2b 44 29 d6 7b d7 ac 8e 5e a7 fe 92 4e 20 a6 ec "
      + "66 22 91 f2 54 8d 73 4f 66 34 86 8b 03 9a a5 f9 "
      + "d4 d9 06 b2 d0 cb 85 85 bf 42 85 47 af c9 1c 6e "
      + "20 52 dd cd 00 1c 3e f8 c8 ee fc 3b 6b 2a 82 b6 "
      + "f9 c8 8c 56 f2 e2 c3 cb 0b e4 b8 0d a9 5e ba 37 "
      + "1d 8b 5f 60 f9 25 38 74 3d db b5 da 29 72 c7 1f "
      + "e7 b9 f1 b7 90 26 8a 0e 77 0f c5 eb 4d 5d d8 52 "
      + "47 d4 8a e2 ec 3f 26 25 5a 39 85 52 02 06 a1 f2 "
      + "68 e4 83 e9 db b1 d5 ca b1 90 91 76 06 de 31 e7 "
      + "c5 18 2d 8f 15 1b f4 1d fe cc ae d7 cd e6 90 b2 "
      + "16 47 10 6b 49 0c 72 9d 54 a8 fe 28 02 a6 d1 26 ";


  final String encryptionP =
      "f1 23 bf e5 3d e9 7a 56 9d 91 ad cf 55 6f a6 25" +
      "ad 30 f3 fd 3d 81 1f 9e 91 e6 af 44 b6 e7 80 cb" +
      "0f 32 78 29 fb 21 19 0a e2 80 66 46 d7 28 cd 9b" +
      "65 31 13 2b 1e bf ef 12 72 99 30 60 f1 ce 70 b1" +
      "24 39 30 91 ee 85 93 b7 27 36 7e db ba 00 9e c5" +
      "be 17 c4 ac ee 12 0c 84 12 67 d4 76 31 a1 6c 36" +
      "a6 d1 c9 99 73 c1 b0 b5 a8 35 bf 39 fe af e8 f6" +
      "42 1f d9 c2 a9 0b c2 79 76 65 9e 67 bc 83 12 4d";

  final String encryptionQ =
      "ea 98 39 b7 e3 7e a8 9b bd a2 7e 4c 93 47 1c b4" +
      "fd 92 18 9a 0a 96 bc b4 d7 56 93 f1 8a 5c 2f 74" +
      "2a f9 e3 6f de 67 9f bd 9e ae 34 5f a2 69 52 7b" +
      "69 65 02 1c 4b df 54 d6 85 bf 08 96 0c c9 76 f6" +
      "8d ca 21 ce bf 44 f2 68 a5 9d ab 8d 1a 25 e5 19" +
      "f5 14 7e 1f 45 fe 28 7d 74 cf 72 5b ec 13 26 d3" +
      "42 12 c5 6c f4 ff fa 20 2f 57 b6 8e e8 cc a9 43" +
      "f3 c1 38 c4 cd e3 3b df 2c 94 40 df 65 32 24 45";

  final String encryptionDP1 =
      "ca 0c 9b 60 b8 e4 a6 06 67 56 c6 5d 20 88 41 9d" +
      "f6 25 3b 7b 68 8a 85 f4 f6 e9 64 d8 5d ad 52 a4" +
      "52 62 86 7f 1e 96 18 06 9f cc d8 65 e9 28 9e 46" +
      "e3 9e 20 22 94 4c 5c 44 87 d3 45 cf 25 2d 46 0d" +
      "97 7d 77 ed fe fe db cb ae 46 a2 3a f7 fa 47 0f" +
      "07 7d a0 e5 09 42 04 4c b1 a3 60 49 7c c2 76 0a" +
      "c0 f2 ad 4a 2f cd 0e 84 d7 a1 d9 4d fd d2 65 8f" +
      "d9 ce 18 47 5c 1f a7 5e e0 ce ba d0 cf 0a c0 4d";

  final String encryptionDQ1 =
      "52 81 71 23 3c 4e 4a 6c 63 b8 67 64 f5 13 38 84" +
      "6a fd db cb 29 58 34 4c 01 c4 00 4a 1d d8 28 14" +
      "5a 1d 02 a1 50 7d ef 4f 58 24 7a 64 fc 10 c0 a2" +
      "88 c1 ae 89 57 21 d7 8b 8f 04 4d b7 c0 0d 86 da" +
      "55 a9 b6 54 29 2e cd 76 82 70 be 69 e4 bd 59 22" +
      "d4 ef fd 1f 70 95 5f 96 27 e3 e1 9b 74 9e 93 b4" +
      "0e f3 dd 1d 61 d9 39 15 e2 b0 9d 93 0b 4b 17 68" +
      "bf ac c0 13 6f 39 b0 cf df b4 d0 50 01 1e 2e 65";

  final String encryptionPQ =
      "df 2e b2 32 2c c2 da ab f4 d1 46 55 08 f4 15 21" +
      "cd a7 ce ff 23 eb e6 1d 00 d4 41 ee 72 8d da 5d" +
      "16 c7 bf 92 0c d9 5f 34 be b4 fe 32 ee 81 7e f3" +
      "36 2e 0b cd 1d 12 45 f7 b0 77 93 ea a1 90 dc 5a" +
      "37 fd af 4c 68 e2 ca 13 97 2d 7f 51 48 b7 96 b6" +
      "fb 6d 7a dd a0 7b d2 cd 13 be 98 ce be d1 ed c6" +
      "ca 41 2e 39 53 50 c5 9a 1d 84 2b c4 aa 2f 3c 0b" +
      "24 3f de 7d fd 95 35 6f 24 39 25 1a 11 72 c4 5e";

  final String encryptedData =
      "60 42 e7 45 58 9a f0 3a f8 75 20 f9 3c 45 d8 c3" +
      "59 85 ad a1 16 1a 37 d8 22 e9 f9 46 0f c7 5f cf" +
      "01 79 d8 49 1b 8f 5d 1e 4d e8 ce b3 1e 07 c4 86" +
      "5c 5a 3e fd bb b6 9a 88 03 b8 9e e6 5a 43 0a 58" +
      "09 c7 07 56 91 50 b5 80 bb 68 6a 94 c5 54 1c 46" +
      "ad cd 82 79 60 ce 24 4f f6 88 38 7d 16 16 e8 5b" +
      "4d 17 80 c6 48 36 06 cf 92 4b 54 f0 80 cf 41 54" +
      "e6 68 29 bf 6e 53 24 81 04 8e c4 1f ad c0 7d 75" +
      "5b b3 4b b2 81 45 21 9c b3 0d 47 d0 d6 18 70 91" +
      "80 e9 03 03 ff 9e f0 90 18 be d3 da 75 76 1d a7" +
      "94 81 1f 96 bc 9e 8d 7c 4b a1 b5 94 6b da 0b d3" +
      "13 fa ec 4c 99 3e d2 74 8e ed 8c ce 4b db 52 0b" +
      "a7 db 16 5f 9f e5 6a a8 45 4d 6f f3 38 74 fe ee" +
      "bf 29 de 2d f5 b7 f0 0a a1 d9 fb 07 3f c4 06 7b" +
      "58 dc 50 62 4e 12 7f 71 1d de 2c c2 cf da b4 91" +
      "9c cf 28 c8 36 60 df c2 27 b0 f5 00 ec 1f 90 4f";

  final String clearData =
      "2a ac ec 86 f4 23 dd 92 5e c1 58 82 2a 74 8c be 6c 31 a0";

  private byte[] createSha1DigestInfo(String data) throws NoSuchAlgorithmException {
    MessageDigest mac = MessageDigest.getInstance("SHA1");
    return mergeByteArrays(toByteArray("30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 "),
                           mac.digest(toByteArray(data)));
  }

  /**
   * Receive more than 256 bytes from the card using command chaining.
   */
  private byte[] receiveLong(ResponseAPDU r) throws CardException {
    byte[] data = new byte[0];
    for (; ; ) {
      data = mergeByteArrays(data, r.getData());
      if (r.getSW() == 0x9000) {
        break;
      }
      assertEquals(0x61, r.getSW1());
      r = card.sendAPDU(0, 0xC0, 0, 0, r.getSW2());
    }
    return data;
  }

  /**
   * Use command chaining to send key data to the card and check the response status.
   *
   * @return the result of the last APDU in the chain.
   */
  private ResponseAPDU sendLong(int cla, int ins, int p1, int p2, byte[] data, int maxAPDULength)
      throws CardException {
    ResponseAPDU r = null;
    assertNotEquals(0, data.length);
    for (int i = 0; i < data.length; i += maxAPDULength) {
      int dataSize = data.length - i > maxAPDULength ? maxAPDULength : data.length - i;
      r = card.sendAPDU(cla, ins, p1, p2, Arrays.copyOfRange(data, i, i + dataSize));
      assertTrue("Unexpected SW while sending a long APDU",
                 r.getSW() == 0x9000 | r.getSW1() == 0x61);
    }
    return r;
  }

  private ResponseAPDU sendKey(byte[] data) throws CardException {
    return sendLong(0, Gpg.CMD_PUT_KEY, 0x3F, 0xFF, data, 255);
  }

  @Test
  public void ImportSignatureKey() throws CardException, NoSuchAlgorithmException {
    // ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15sign-vectors.txt

    byte[]
        data =
        encodeCRTKey(0xB6, signatureP, signatureQ, signatureDP1, signatureDQ1, signaturePQ);
    byte[] encodedPublicKey = encodePublicKey(signatureP, signatureQ, signatureDP1);

    // Submit PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    sendKey(data);

    // PW1 is needed to sign.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Example 15.5 from pkcs1v15sign-vectors.txt
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));

    // Submit partial key
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_KEY, 0x3F, 0xFF,
                                       Arrays.copyOfRange(data, 0, 255)));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Make sure we don't compute the signature.
    assertSWOnly(0x6A82, card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                                       createSha1DigestInfo(signatureTestData), 256));

    sendLong(0, Gpg.CMD_PUT_KEY, 0x3F, 0xFF, data, 128);

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));

    byte[] publicKeyData = receiveLong(
        card.sendAPDU(0, Gpg.CMD_GENERATE_ASYMETRIC, 0x81, 0, "B6 00", 0));
    assertArrayEquals("Expected: " + bytesToHex(encodedPublicKey), encodedPublicKey, publicKeyData);
  }

  @Test
  public void signatureCounter() throws CardException, NoSuchAlgorithmException {
    byte[]
        data =
        encodeCRTKey(0xB6, signatureP, signatureQ, signatureDP1, signatureDQ1, signaturePQ);
    // Submit PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    sendKey(data);

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    assertSWData(0x9000, "00 00 00",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    assertSWData(0x9000, "00 00 01",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    assertSWData(0x9000, "00 00 02",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));

    // Reload the key
    sendKey(data);
    assertSWData(0x9000, "00 00 00",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));

    // Perform another signature.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    // Check the counter
    assertSWData(0x9000, "00 00 01",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
    clearCard();
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Check the counter
    assertSWData(0x9000, "00 00 00",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
    // Check that the signature key is not operable.
    assertSWOnly(0x6A82, card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                                       createSha1DigestInfo(signatureTestData), 256));
  }

  @Test
  public void setPW1Usage() throws CardException, NoSuchAlgorithmException {
    byte[]
        data =
        encodeCRTKey(0xB6, signatureP, signatureQ, signatureDP1, signatureDQ1, signaturePQ);
    // Submit PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    sendKey(data);
    // PIN valid for one signature only.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "00"));

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    assertSWData(0x9000, "00 00 01",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
    // The second signature should fail.
    assertSWOnly(0x6985,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    // And the signature counter hasn't changed.
    assertSWData(0x9000, "00 00 01",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));

    // PIN good for multiple signatures.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "01"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));

    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    assertSWData(0x9000, "00 00 02",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
    assertSWData(0x9000, expectedSignature,
                 card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                               createSha1DigestInfo(signatureTestData), 256));
    assertSWData(0x9000, "00 00 03",
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (SIGNATURE_COUNTER.tag / 256),
                               (byte) (SIGNATURE_COUNTER.tag & 0xFF)));
  }

  @Test
  public void generateKey() throws CardException, NoSuchAlgorithmException,
                                   InvalidKeySpecException, SignatureException,
                                   InvalidKeyException {
    // Submit PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));

    byte[] publicKeyData = receiveLong(
        card.sendAPDU(0, Gpg.CMD_GENERATE_ASYMETRIC, 0x80, 0, "B6 00", 0));
    TLVDer pk = TLVDer.GetNext(publicKeyData, 0);
    assertEquals(TLVDer.Status.OK, pk.status);
    assertEquals(0x7F49, pk.tag);

    TLVDer tlv = TLVDer.GetNext(pk.data, 0);
    assertEquals(TLVDer.Status.OK, tlv.status);
    assertEquals(0x82, tlv.tag);
    byte[] e = tlv.data;

    tlv = TLVDer.GetNext(pk.data, tlv.currentOffset);
    assertEquals(TLVDer.Status.OK, tlv.status);
    assertEquals(0x81, tlv.tag);
    byte[] modulus = tlv.data;
    assertEquals(2048 / 8, modulus.length);

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    ResponseAPDU r = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x9E, 0x9A,
                                                    createSha1DigestInfo(signatureTestData), 256));
    assertEquals(2048 / 8, r.getData().length);
    Signature signature = Signature.getInstance("SHA1withRSA");
    KeyFactory keyMaker = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(1, modulus),
                                                       new BigInteger(1, e));
    RSAPublicKey pubKey = (RSAPublicKey) keyMaker.generatePublic(pubKeySpec);
    signature.initVerify(pubKey);
    signature.update(toByteArray(signatureTestData));
    assertTrue(signature.verify(r.getData()));
  }

  @Test
  public void decrypt() throws CardException {
    byte[] data = encodeCRTKey(0xB8, encryptionP, encryptionQ, encryptionDP1, encryptionDQ1,
                               encryptionPQ);
    // Submit PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    // Load the encrytion key.
    sendKey(data);
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));

    byte[] eData = toByteArray("00" + encryptedData);
    ResponseAPDU r = sendLong(0, Gpg.CMD_COMPUTE_PSO, 0x80, 0x86, eData, 255);
    assertArrayEquals("Expected: " + clearData, toByteArray(clearData), r.getData());

    clearCard();
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Check that the decrytion key is not operable.
    assertSWOnly(0x6A82, card.sendAPDU(0, Gpg.CMD_COMPUTE_PSO, 0x80, 0x86,
                                       Arrays.copyOfRange(eData, 0, 128)));
  }

  @Test
  public void internalAuthenticate()
      throws CardException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair key = keyGen.generateKeyPair();
    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key.getPrivate();
    byte[] data = encodeCRTKey(0xA4, bytesToHex(trimmedBigInteger(privateKey.getPrimeP())),
                               bytesToHex(trimmedBigInteger(privateKey.getPrimeQ())),
                               bytesToHex(trimmedBigInteger(privateKey.getPrimeExponentP())),
                               bytesToHex(trimmedBigInteger(privateKey.getPrimeExponentQ())),
                               bytesToHex(trimmedBigInteger(privateKey.getCrtCoefficient())));

    // Submit PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    // Load the encrytion key.
    sendKey(data);
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    String testData = "33 A8 43 1F E0 44 B8 55";
    ResponseAPDU r = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_INTERNAL_AUTHENTICATE, 0, 0,
                                                    testData));

    // Compute signature as described in 7.2.10
    byte[] byteData = toByteArray(testData);
    byte[] pad = new byte[256 - 3 - byteData.length];
    Arrays.fill(pad, (byte) 0xFF);
    byte[] expected = mergeByteArrays(toByteArray("00 01"), pad, new byte[1], byteData);
    BigInteger s = new BigInteger(1, r.getData());
    RSAPublicKey pkey = (RSAPublicKey) key.getPublic();
    BigInteger se = s.modPow(pkey.getPublicExponent(), pkey.getModulus());
    byte[] computedAuth = se.toByteArray();
    if (computedAuth.length < 256) {
      computedAuth = mergeByteArrays(new byte[256 - computedAuth.length], computedAuth);
    }
    assertArrayEquals(bytesToHex(computedAuth), computedAuth, expected);
    // Make sure that the authentication key is cleared.
    clearCard();
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Check that the decryption key is not operable.
    assertSWOnly(0x6A82, card.sendAPDU(0, Gpg.CMD_INTERNAL_AUTHENTICATE, 0, 0, testData));
  }

}