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

package net.ss3t.javacard;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static java.lang.String.format;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CardUtils {

  /**
   * Create a human friendly representation of a @CommandAPDU.
   */
  public static String formatCommandAPDU(CommandAPDU command) {
    if (command.getNc() > 0) {
      if (command.getNe() > 0) {
        return format("[Sent] %02X %02X %02X %02X Lc = %02X Le = %02X ", command.getCLA(),
                      command.getINS(), command.getP1(), command.getP2(), command.getNc(),
                      command.getNe())
               + HexString.bytesToHex(command.getData());
      } else {
        return format("[Sent] %02X %02X %02X %02X %02X  ", command.getCLA(),
                      command.getINS(), command.getP1(), command.getP2(), command.getNc())
               + HexString.bytesToHex(command.getData());
      }
    } else {
      return format("[Sent] %02X %02X %02X %02X %02X  ", command.getCLA(),
                    command.getINS(), command.getP1(), command.getP2(), command.getNe());
    }
  }

  public static String formatResponseAPDU(ResponseAPDU response) {
    if (response.getData().length > 0) {
      return format("[Received] SW: %04X Data: ", response.getSW()) + HexString.bytesToHex(
          response.getData());
    } else {
      return format("[Received] SW: %04X", response.getSW());
    }
  }

  public static void assertSWOnly(int expectedSW, ResponseAPDU response) {
    assertEquals(format("Invalid SW: got %04X expected %04X", response.getSW(), expectedSW),
                 expectedSW, response.getSW());
    assertEquals("Unexpected data.", 0, response.getData().length);
  }

  public static void assertSWOnly(String message, int expectedSW, ResponseAPDU response) {
    assertEquals(message + format("Invalid SW: got %04X expected %04X", response.getSW(),
                                  expectedSW), expectedSW, response.getSW());
    assertEquals(message + "Unexpected data.", 0, response.getData().length);
  }

  public static void assertSWData(int expectedSW, byte[] expectedData, ResponseAPDU response) {
    assertEquals(format("Invalid SW: got %04X expected %04X", response.getSW(),
                        expectedSW), expectedSW, response.getSW());
    assertArrayEquals(expectedData, response.getData());
  }

  public static void assertSWData(int expectedSW, String expectedDataHex, ResponseAPDU response) {
    assertEquals(format("Invalid SW: got %04X expected %04X", response.getSW(),
                        expectedSW), expectedSW, response.getSW());
    assertArrayEquals(HexString.toByteArray(expectedDataHex), response.getData());
  }

  public static ResponseAPDU assertSW(int expectedSW, ResponseAPDU response) {
    assertEquals(format("Invalid SW: got %04X expected %04X", response.getSW(), expectedSW),
                 expectedSW, response.getSW());
    return response;
  }

}
