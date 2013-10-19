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

import org.junit.Test;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import static net.ss3t.javacard.CardUtils.assertSW;
import static net.ss3t.javacard.CardUtils.assertSWOnly;
import static org.junit.Assert.assertEquals;

public abstract class GpgPINTest extends GpgTest {

  public GpgPINTest(CardInterfaceBuilder builder) {
    super(builder);
  }

  @Test
  public void submitPin1() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));

    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35"));

    assertSWOnly(0x6700,
                 card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, new byte[Gpg.MAX_PIN_LENGTH + 1]));

    assertSWOnly(0x63C2, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36 37"));
    // Check that 0x82 uses the same counter.
    assertSWOnly(0x63C1, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x82, "31 32 33 34 35 36 37 38"));
    // Check that the counter is reset after a good presentation.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));

    // Lock the PW1
    for (int i = 0; i < Gpg.MAX_TRIES_PIN1; ++i) {
      assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN1 - i - 1,
                   card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "30 30 30 30 30 30"));
    }
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 35"));
    // Submit the good PIN, it should fail.
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    clearCard();
  }

  @Test
  public void submitPin3() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37"));
    assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN3 - 1,
                 card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38 39"));

    for (int i = 1; i < Gpg.MAX_TRIES_PIN3; ++i) {
      assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN3 - i - 1,
                   card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "30 32 33 34 35 36 37 38"));
    }
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 39"));
    // Submitting the good PW3 should fail.
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    clearCard();
  }

  @Test
  public void changePIN1() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36  41 42 43 44 45 46"));

    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "41 42 43 44 45 46"));

    // Change with the wrong password.
    assertSWOnly(0x63C2, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "31 32 33 34 35 36  41 42 43 44 45 46"));
    // Check that the password is unchanged.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "41 42 43 44 45 46"));
    // Change the length
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "41 42 43 44 45 46  31 32 33 34 35 36 37 38"));
    // Check the new PIN.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36 37 38"));
    // New password too short (with the new PIN length
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 37 38 41 42 43 44 45"));
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 37 38"));
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81, "31 32 33 34"));
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81, ""));
    // Make sure that we can change the PIN again.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 37 38 AA BB CC DD EE FF"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "AA BB CC DD EE FF"));
    // Lock the PIN with failed changes
    assertSWOnly(0x63C2, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 AA BB CC DD EE FF"));
    assertSWOnly(0x63C1, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 AA BB CC DD EE FF"));
    assertSWOnly(0x63C0, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 AA BB CC DD EE FF"));
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 AA BB CC DD EE FF"));
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "AA BB CC DD EE FF"));
    clearCard();
  }

  @Test
  public void changePIN3() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "31 32 33 34 35 36 37 38"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x83,
                                       "31 32 33 34 35 36 37 38 41 42 43 44 45 46 47 48"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83, "41 42 43 44 45 46 47 48"));
    // Length change, too short
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x83,
                                       "41 42 43 44 45 46 47 48 31 32 33 34 35 36 37"));
    // Too long
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x83,
                                       new byte[Gpg.MAX_PIN_LENGTH + 9]));
    // 10 byte long.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x83,
                                       "41 42 43 44 45 46 47 48 51 52 53 54 55 56 57 58 59 5A"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83,
                                       "51 52 53 54 55 56 57 58 59 5A"));
    // Change back to 8 bytes
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x83,
                                       "51 52 53 54 55 56 57 58 59 5A 31 32 33 34 35 36 37 38"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83,
                                       "31 32 33 34 35 36 37 38"));
    // Wrong change PIN
    for (int i = 0; i < Gpg.MAX_TRIES_PIN3; ++i) {
      assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN3 - i - 1,
                   card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x83,
                                 "51 52 53 54 55 56 57 58 59 5A 31 32 33 34 35 36 37 38"));
    }
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83,
                                       "31 32 33 34 35 36 37 38"));

    clearCard();
  }

  @Test
  public void resetPIN() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Lock PW1
    for (int i = 0; i < Gpg.MAX_TRIES_PIN1; ++i) {
      assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN1 - i - 1,
                   card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "30 30 30 30 30 30"));
    }
    // Check that a good PW1 fails.
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    // Try to unlock without submitting PW3
    assertSWOnly(0x6985, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 2, 0x81,
                                       "41 42 43 44 45 46"));
    // Good PW3
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83,
                                       "31 32 33 34 35 36 37 38"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 2, 0x81,
                                       "41 42 43 44 45 46"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "41 42 43 44 45 46"));
    // Unlock with new PW1 too short.
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 2, 0x81,
                                       "41 42 43 44 45"));
    // Unlock with new PW1 too long.
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 2, 0x81,
                                       new byte[Gpg.MAX_PIN_LENGTH + 1]));
    // Unlock with new PW1 length.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 2, 0x81,
                                       "31 32 33 34 35 36 37"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "31 32 33 34 35 36 37"));
    // Make sure we updated the length so we can change PW1.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "31 32 33 34 35 36 37 41 42 43 44 45 46 47"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "41 42 43 44 45 46 47"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "41 42 43 44 45 46 47 31 32 33 34 35 36"));
  }

  @Test
  public void resetPINWithResetCode() throws CardException {
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "31 32 33 34 35 36"));
    for (int i = 0; i < Gpg.MAX_TRIES_PIN1; ++i) {
      assertSWOnly(0x63C0 + Gpg.MAX_TRIES_PIN1 - i - 1,
                   card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81, "30 30 30 30 30 30"));
    }
    // Without a Reset Code.
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 0, 0x81,
                                       "31 32 33 34 35 36 37 38 51 52 53 54 55 56"));
    // Present PW3.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x83,
                                       "31 32 33 34 35 36 37 38"));
    // This should still fail.
    assertSWOnly(0x6983, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 0, 0x81,
                                       "31 32 33 34 35 36 37 38 51 52 53 54 55 56"));
    // Write a reset code.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_PUT_DATA, 0, 0xD3,
                                       "50 51 52 53 54 55 56 57"));
    // Should reset the PIN to 61 62 63 64 65 66 67
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 0, 0x81,
                                       "50 51 52 53 54 55 56 57 61 62 63 64 65 66 67"));
    // Check the new PIN
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "61 62 63 64 65 66 67"));
    // Make sure we updated the length so we can change PW1.
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_CHANGE_REFERENCE_DATA, 0, 0x81,
                                       "61 62 63 64 65 66 67 31 32 33 34 35 36"));
    assertSWOnly(0x9000, card.sendAPDU(0, Gpg.CMD_VERIFY, 0, 0x81,
                                       "31 32 33 34 35 36"));
    // Unlock with new PW1 too short.
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 0, 0x81,
                                       "50 51 52 53 54 55 56 57 41 42 43 44 45"));
    assertSWOnly(0x6700, card.sendAPDU(0, Gpg.CMD_RESET_RETRY_COUNTER, 0, 0x81,
                                       "50 51 52 53 54 55 56 57 " + new String(
                                           new char[Gpg.MAX_PIN_LENGTH + 1]).replace("\0", " 30")));

    ResponseAPDU response = assertSW(0x9000, card.sendAPDU(0, Gpg.CMD_GET_DATA, 0, 0xC4, 7));
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[1]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[2]);
    assertEquals(Gpg.MAX_PIN_LENGTH, response.getData()[3]);
    // No bad presentation so far but RC not set.
    assertEquals(Gpg.MAX_TRIES_PIN1, response.getData()[4]);
    assertEquals(Gpg.MAX_TRIES_RC, response.getData()[5]);
    assertEquals(Gpg.MAX_TRIES_PIN3, response.getData()[6]);
  }
}