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

import net.ss3t.javacard.CardInterface;
import net.ss3t.javacard.CardInterfaceBuilder;
import net.ss3t.javacard.TestCard;

import org.junit.Before;

import javax.smartcardio.CardException;

import static net.ss3t.javacard.CardUtils.assertSWOnly;
import static org.junit.Assert.assertTrue;

public abstract class GpgTest {

  public static final byte[] appletAID = {
      (byte) 0xD2, (byte) 0x76, (byte) 0x00, (byte) 0x01, (byte) 0x24,  // FSF RID
      (byte) 0x01, (byte) 0x02, (byte) 0x00,  // GPG Applet, Version 2.00
      (byte) 0x00, (byte) 0x00,  // Manufacturer.
      (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44,  // Serial number
      (byte) 0x00, (byte) 0x00};  // RFU.

  protected CardInterface cardInterface;
  protected TestCard card;
  protected final CardInterfaceBuilder cardInterfaceBuilder;

  public GpgTest(CardInterfaceBuilder builder) {
    cardInterfaceBuilder = builder;
  }

  @Before
  public void initialize() throws CardException {
    cardInterface = cardInterfaceBuilder.getCardInterface();
    card = new TestCard(cardInterface);
    card.reset();
    assertTrue("Failed to select the applet.", card.selectApplet(appletAID));
  }

  /**
   * Use the card reset sequence to wipe the card.
   */
  void clearCard() throws CardException {
    // Lock both PINs.
    for (int i = 0; i < Gpg.MAX_TRIES_PIN1; ++i) {
      card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "FF FF FF FF FF FF");
    }
    for (int i = 0; i < Gpg.MAX_TRIES_PIN3; ++i) {
      card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "FF FF FF FF FF FF FF FF");
    }
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_TERMINATE_DF, 0, 0));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_ACTIVATE_FILE, 0, 0));
  }

}
