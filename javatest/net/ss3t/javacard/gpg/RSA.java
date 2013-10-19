package net.ss3t.javacard.gpg;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.math.BigInteger;

import static net.ss3t.javacard.HexString.bytesToHex;
import static net.ss3t.javacard.HexString.toByteArray;

/**
 */
@RunWith(JUnit4.class)
public class RSA {

  @Test
  public void crt() {
    /*
    BigInteger m = new BigInteger(1, toByteArray(
"a8 b3 b2 84 af 8e b5 0b 38 70 34 a8 60 f1 46 c4 91 9f 31 87 63 cd 6c 55 98 c8 ae 48 11 a1 e0 ab" +
"c4 c7 e0 b0 82 d6 93 a5 e7 fc ed 67 5c f4 66 85 12 77 2c 0c bc 64 a7 42 c6 c6 30 f5 33 c8 cc 72" +
"f6 2a e8 33 c4 0b f2 58 42 e9 84 bb 78 bd bf 97 c0 10 7d 55 bd b6 62 f5 c4 e0 fa b9 84 5c b5 14" +
"8e f7 39 2d d3 aa ff 93 ae 1e 6b 66 7b b3 d4 24 76 16 d4 f5 ba 10 d4 cf d2 26 de 88 d3 9f 16 fb"));

    BigInteger signatureP = new BigInteger(1, toByteArray(
"d3 27 37 e7 26 7f fe 13 41 b2 d5 c0 d1 50 a8 1b 58 6f b3 13 2b ed 2f 8d 52 62 86 4a 9c b9 f3 0a" +
    "f3 8b e4 48 59 8d 41 3a 17 2e fb 80 2c 21 ac f1 c1 1c 52 0c 2f 26 a4 71 dc ad 21 2e ac 7c a3 9d"));

    BigInteger signatureQ = new BigInteger(1, toByteArray(
        "cc 88 53 d1 d5 4d a6 30 fa c0 04 f4 71 f2 81 c7 b8 98 2d 82 24 a4 90 ed be b3 3d 3e 3d 5c c9 3c" +
        "47 65 70 3d 1d d7 91 64 2f 1f 11 6a 0d d8 52 be 24 19 b2 af 72 bf e9 a0 30 e8 60 b0 28 8b 5d 77"));
      */

/*
    BigInteger signatureP = new BigInteger(1, toByteArray(
        "00 f4 4f 5e 42 46 39 1f 48 2b 2f 52 96 e3 60 2e b3" +
"4a a1 36 42 77 10 f7 c0 41 6d 40 3f d6 9d 4b 29" +
"13 0c fe be f3 4e 88 5a bd b1 a8 a0 a5 f0 e9 b5" +
"c3 3e 1f c3 bf c2 85 b1 ae 17 e4 0c c6 7a 19 13" +
"dd 56 37 19 81 5e ba f8 51 4c 2a 7a a0 01 8e 63" +
"b6 c6 31 dc 31 5a 46 23 57 16 42 3d 11 ff 58 03" +
"4e 61 06 45 70 36 06 91 9f 5c 7c e2 66 0c d1 48"+
"bd 9e fc 12 3d 9c 54 b6 70 55 90 d0 06 cf cf 3f"));

    BigInteger signatureQ = new BigInteger(1, toByteArray(
       "00 e9 d4 98 41 e0 e0 a6 ad 0d 51 78 57 13 3e 36 dc" +
"72 c1 bd d9 0f 91 74 b5 2e 26 57 0f 37 36 40 f1" +
"c1 85 e7 ea 8e 2e d7 f1 e4 eb b9 51 f7 0a 58 02" +
"36 33 b0 09 7a ec 67 c6 dc b8 00 fc 1a 67 f9 bb" +
"05 63 61 0f 08 eb c8 74 6a d1 29 77 21 36 eb 1d" +
"da f4 64 36 45 0d 31 83 32 a8 49 82 fe 5d 28 db" +
"e5 b3 e9 12 40 7c 3e 0e 03 10 0d 87 d4 36 ee 40" +
"9e ec 1c f8 5e 80 ab a0 79 b2 e6 10 6b 97 bc ed"));
*/

    BigInteger p = new BigInteger(1, toByteArray(
                        "f1 23 bf e5 3d e9 7a 56 9d 91 ad cf 55 6f a6 25" +
"ad 30 f3 fd 3d 81 1f 9e 91 e6 af 44 b6 e7 80 cb" +
"0f 32 78 29 fb 21 19 0a e2 80 66 46 d7 28 cd 9b" +
"65 31 13 2b 1e bf ef 12 72 99 30 60 f1 ce 70 b1" +
"24 39 30 91 ee 85 93 b7 27 36 7e db ba 00 9e c5" +
"be 17 c4 ac ee 12 0c 84 12 67 d4 76 31 a1 6c 36" +
"a6 d1 c9 99 73 c1 b0 b5 a8 35 bf 39 fe af e8 f6" +
"42 1f d9 c2 a9 0b c2 79 76 65 9e 67 bc 83 12 4d"));
    BigInteger q = new BigInteger(1, toByteArray(
 "ea 98 39 b7 e3 7e a8 9b bd a2 7e 4c 93 47 1c b4" +
"fd 92 18 9a 0a 96 bc b4 d7 56 93 f1 8a 5c 2f 74" +
"2a f9 e3 6f de 67 9f bd 9e ae 34 5f a2 69 52 7b" +
"69 65 02 1c 4b df 54 d6 85 bf 08 96 0c c9 76 f6" +
"8d ca 21 ce bf 44 f2 68 a5 9d ab 8d 1a 25 e5 19" +
"f5 14 7e 1f 45 fe 28 7d 74 cf 72 5b ec 13 26 d3" +
"42 12 c5 6c f4 ff fa 20 2f 57 b6 8e e8 cc a9 43" +
"f3 c1 38 c4 cd e3 3b df 2c 94 40 df 65 32 24 45"));

    BigInteger m = p.multiply(q);

    BigInteger e = BigInteger.valueOf(0x10001);
    BigInteger p_m_1 = p.subtract(BigInteger.valueOf(1));
    BigInteger q_m_1 = q.subtract(BigInteger.valueOf(1));
    BigInteger m_phi = (p_m_1.multiply(q_m_1)).divide(p_m_1.gcd(q_m_1));
    BigInteger d = e.modInverse(m_phi);
    BigInteger d2 = d.gcd(q);
    String dtext = bytesToHex(d.toByteArray());
  }

}
