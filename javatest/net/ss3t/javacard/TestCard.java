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

import java.util.logging.Logger;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static net.ss3t.javacard.CardUtils.formatCommandAPDU;
import static net.ss3t.javacard.CardUtils.formatResponseAPDU;
import static net.ss3t.javacard.HexString.toByteArray;

public class TestCard {

  private final CardInterface cardInterface;
  private static final Logger logger = Logger.getLogger("TestCard");

  public TestCard(CardInterface cardInterface) {
    this.cardInterface = cardInterface;
  }

  public ResponseAPDU sendAPDU(CommandAPDU command) throws CardException {
    logger.info(formatCommandAPDU(command));
    ResponseAPDU r = cardInterface.sendAPDU(command);
    logger.info(formatResponseAPDU(r));
    return r;
  }

  public ResponseAPDU sendAPDU(byte[] apdu) throws CardException {
    return sendAPDU(new CommandAPDU(apdu));
  }

  public ResponseAPDU sendAPDU(byte[] apdu, int offset, int length) throws CardException {
    return sendAPDU(new CommandAPDU(apdu, offset, length));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2) throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data) throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, data));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, String hexData)
      throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, toByteArray(hexData)));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, String hexData, int le)
      throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, toByteArray(hexData), le));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data, int le)
      throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, data, le));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data, int dataOffset,
                               int dataLength) throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, data, dataOffset, dataLength));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data, int dataOffset,
                               int dataLength, int le) throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, data, dataOffset, dataLength, le));
  }

  public ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, int le) throws CardException {
    return sendAPDU(new CommandAPDU(cla, ins, p1, p2, le));
  }

  public void reset() throws CardException {
    logger.info("[Card reset]");
    cardInterface.reset();
  }

  public boolean selectApplet(byte[] aid) throws CardException {
    return cardInterface.selectApplet(aid);
  }

}