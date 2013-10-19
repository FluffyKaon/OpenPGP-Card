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

package net.ss3t.javacard.PhysicalCard;

import net.ss3t.javacard.CardInterface;

import java.util.List;
import java.util.logging.Logger;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import static net.ss3t.javacard.CardUtils.formatCommandAPDU;
import static net.ss3t.javacard.HexString.bytesToHex;

/**
 * Uses a physical smart card.
 */
public class PhysicalCard implements CardInterface {

  protected CardChannel channel = null;
  protected Card card = null;
  protected CardTerminal reader = null;

  protected static final Logger logger = Logger.getLogger("Physical Card");

  public boolean initialize() throws CardException {
    List<CardTerminal> readersWithCards = TerminalFactory.getDefault().terminals()
        .list(CardTerminals.State.CARD_PRESENT);
    if (readersWithCards.isEmpty()) {
      logger.severe("No card found.");
      return false;
    }
    reader = readersWithCards.get(0);
    logger.info("Reader: " + reader);
    card = reader.connect("*");
    logger.info("Card: " + card);
    channel = card.getBasicChannel();
    return true;
  }

  @Override
  public void reset() throws CardException {
    card.disconnect(true);
    card = reader.connect("*");
    channel = card.getBasicChannel();
  }

  @Override
  public boolean selectApplet(byte[] aid) throws CardException {
    CommandAPDU select = new CommandAPDU(0, 0xa4, 4, 0, aid);
    logger.info(formatCommandAPDU(select));
    ResponseAPDU r = channel.transmit(select);
    logger.info(r.getSW() == 0x9000 ? "[OK]" : String.format("[%04X]", r.getSW()) +
                                               " Applet selection: " + bytesToHex(aid));
    return r.getSW() == 0x9000;
  }

  @Override
  public ResponseAPDU sendAPDU(CommandAPDU command) throws CardException {
    return channel.transmit(command);
  }
}
