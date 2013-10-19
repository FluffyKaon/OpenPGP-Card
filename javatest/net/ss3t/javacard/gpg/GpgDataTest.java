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
import net.ss3t.javacard.TLVDer;

import org.junit.Test;

import java.util.Arrays;
import java.util.Random;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import static net.ss3t.javacard.CardUtils.assertSW;
import static net.ss3t.javacard.CardUtils.assertSWData;
import static net.ss3t.javacard.CardUtils.assertSWOnly;
import static net.ss3t.javacard.HexString.bytesToHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;


public abstract class GpgDataTest extends GpgTest {

  public GpgDataTest(CardInterfaceBuilder builder) {
    super(builder);
  }

  @Test
  public void getAID() throws CardException {
    assertSWData(0x9000, appletAID,
                 card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0x4F));
  }

  @Test
  public void dataWriteAndRead() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    Random random = new Random();
    for (DataObject dataObject : DataObject.values()) {
      if (dataObject.writeAccess != Access.NEVER) {
        byte[] data = new byte[dataObject.maxLength];
        random.setSeed(dataObject.tag);
        random.nextBytes(data);
        assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, (byte) (dataObject.tag / 256),
                                           (byte) (dataObject.tag & 0xFF), data));
      }
    }

    // Re-read all the objects that are individually readable.
    for (DataObject dataObject : DataObject.values()) {
      if (dataObject.writeAccess != Access.NEVER && !dataObject.groupedRead) {
        byte[] data = new byte[dataObject.maxLength];
        random.setSeed(dataObject.tag);
        random.nextBytes(data);
        assertSWData(0x9000, data, card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (dataObject.tag / 256),
                                                 (byte) (dataObject.tag & 0xFF)));
      }
    }
    // Check the fingerprints.
    byte[] rand = new byte[DataObject.FINGERPRINT_1.maxLength];
    byte[] expected = new byte[DataObject.FINGERPRINT_1.maxLength * 3];
    random.setSeed(DataObject.FINGERPRINT_1.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, 0, rand.length);
    random.setSeed(DataObject.FINGERPRINT_2.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, rand.length, rand.length);
    random.setSeed(DataObject.FINGERPRINT_3.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, 2 * rand.length, rand.length);
    assertSWData(0x9000, expected, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC5, 0));

    // CA Fingerprints
    random.setSeed(DataObject.CA_FINGERPRINT_1.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, 0, rand.length);
    random.setSeed(DataObject.CA_FINGERPRINT_2.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, rand.length, rand.length);
    random.setSeed(DataObject.CA_FINGERPRINT_3.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, 2 * rand.length, rand.length);
    assertSWData(0x9000, expected, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC6, 0));

    // Generation dates
    rand = new byte[DataObject.GENERATION_TIME_1.maxLength];
    expected = new byte[DataObject.GENERATION_TIME_1.maxLength * 3];
    random.setSeed(DataObject.GENERATION_TIME_1.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, 0, rand.length);
    random.setSeed(DataObject.GENERATION_TIME_2.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, rand.length, rand.length);
    random.setSeed(DataObject.GENERATION_TIME_3.tag);
    random.nextBytes(rand);
    System.arraycopy(rand, 0, expected, 2 * rand.length, rand.length);
    assertSWData(0x9000, expected, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xCD, 0));

    // Make sure that the composite DOs Cardholder Related Data and Application related data
    // make their individual components.
    ResponseAPDU r = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0,
                                                    DataObject.APPLICATION_RELATED_DATA.tag));
    checkCompositeData(r.getData());

    r = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0,
                                       DataObject.CARDHOLDER_RELATED_DATA.tag));
    checkCompositeData(r.getData());
  }

  @Test
  public void writePWStatus() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "00"));
    ResponseAPDU response = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(0, response.getData()[0]);
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "01"));
    ResponseAPDU response2 = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(1, response2.getData()[0]);
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "00 FF FF FF FF FF FF FF"));
    response2 = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertArrayEquals(response.getData(), response2.getData());
    // Too long.
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "00 FF FF FF FF FF FF FF FF"));
    // Bad PIN3
    assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN3 - 1,
                 card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 37"));
    assertSWOnly(0x6982, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xC4, "00"));
    // Good PIN3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
  }

  @Test
  public void readPWStatus() throws CardException {
    ResponseAPDU response = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[1]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[2]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[3]);
    // No bad presentation so far but RC not set.
    assertEquals(Gpg.MAX_TRIES_PIN1, response.getData()[4]);
    assertEquals(0, response.getData()[5]);
    assertEquals(Gpg.MAX_TRIES_PIN3, response.getData()[6]);
    // Bad PIN.
    assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN1 - 1,
                 card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36 37"));
    response = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[1]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[2]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[3]);
    // No bad presentation so far but RC not set.
    assertEquals(Gpg.MAX_TRIES_PIN1 - 1, response.getData()[4]);
    assertEquals(0, response.getData()[5]);
    assertEquals(Gpg.MAX_TRIES_PIN3, response.getData()[6]);
    // Bad PW3
    assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN3 - 1,
                 card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 37"));
    response = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[1]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[2]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[3]);
    // No bad presentation so far but RC not set.
    assertEquals(Gpg.MAX_TRIES_PIN1 - 1, response.getData()[4]);
    assertEquals(0, response.getData()[5]);
    assertEquals(Gpg.MAX_TRIES_PIN3 - 1, response.getData()[6]);
    // Good PW1, PW3 submissions.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    response = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(Gpg.MAX_TRIES_PIN1, response.getData()[4]);
    assertEquals(0, response.getData()[5]);
    assertEquals(Gpg.MAX_TRIES_PIN3, response.getData()[6]);
  }

  @Test
  public void variableLength() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, DataObject.LOGIN.tag, "00"));
    assertSWData(0x9000, "00", card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, DataObject.LOGIN.tag));

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, DataObject.LOGIN.tag, "01 02"));
    assertSWData(0x9000, "01 02", card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, DataObject.LOGIN.tag));

    byte[] tooLong = new byte[DataObject.LOGIN.maxLength + 1];
    Arrays.fill(tooLong, (byte) 0xFF);
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, DataObject.LOGIN.tag,
                                       tooLong));
    assertSWData(0x9000, "01 02", card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, DataObject.LOGIN.tag));
  }

  @Test
  public void cardWipe() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    Random random = new Random();
    for (DataObject dataObject : DataObject.values()) {
      if (dataObject.writeAccess != Access.NEVER) {
        byte[] data = new byte[dataObject.maxLength];
        random.setSeed(dataObject.tag);
        random.nextBytes(data);
        assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, (byte) (dataObject.tag / 256),
                                           (byte) (dataObject.tag & 0xFF), data));
      }
    }

    clearCard();

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    // Now check that all the readable data is zero
    for (DataObject dataObject : DataObject.values()) {
      if (dataObject.readAccess != Access.NEVER) {
        if (dataObject == DataObject.AID ||
            dataObject == DataObject.HISTORICAL_BYTES ||
            dataObject == DataObject.DISCRETIONARY_DOS ||
            dataObject == DataObject.EXTENDED_CAPABILITIES ||
            dataObject == DataObject.ALGORITHM_ATTRIBUTES_1 ||
            dataObject == DataObject.ALGORITHM_ATTRIBUTES_2 ||
            dataObject == DataObject.ALGORITHM_ATTRIBUTES_3 ||
            dataObject == DataObject.CARDHOLDER_RELATED_DATA ||
            dataObject == DataObject.APPLICATION_RELATED_DATA ||
            dataObject == DataObject.PW_STATUS) {
          // The system data isn't cleared. For the compound object (cardholder data, application
          // relate data) we check their individual components.
          continue;
        }
        ResponseAPDU r =
            assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, (byte) (dataObject.tag / 256),
                                           (byte) (dataObject.tag & 0xFF)));
        if (r.getData().length != 0) {
          byte[] zero = new byte[r.getData().length];
          Arrays.fill(zero, (byte) 0);
          assertArrayEquals(zero, r.getData());
        }
      }
    }
  }


  private void checkCompositeData(byte[] compositeData) throws CardException {
    int pos = 0;
    while (pos < compositeData.length) {
      TLVDer tlv = TLVDer.GetNext(compositeData, pos);
      if (tlv.status == TLVDer.Status.END) {
        break;
      }
      assertEquals(TLVDer.Status.OK, tlv.status);
      DataObject cardObject = DataObject.getByTag(tlv.tag);
      assertNotNull("Unknown object returned:" + tlv.tag, cardObject);

      ResponseAPDU singleObject =
          assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, tlv.tag >> 8, tlv.tag & 0xFF, 0));
      assertArrayEquals("Expecting: " + bytesToHex(tlv.data), tlv.data, singleObject.getData());
      // We should never get currentOffset == pos since we need at least a byte for the tag and
      // another for the length.
      assertNotEquals(pos, tlv.currentOffset);
      pos = tlv.currentOffset;
    }
  }


}
