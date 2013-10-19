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
package net.ss3t.javacard.gpg.physical;

import net.ss3t.javacard.CardInterface;
import net.ss3t.javacard.CardInterfaceBuilder;
import net.ss3t.javacard.PhysicalCard.PhysicalCard;

import javax.smartcardio.CardException;

import static org.junit.Assert.assertTrue;

/**
 */
public class GpgTestPhysical implements CardInterfaceBuilder {

  @Override
  public CardInterface getCardInterface() throws CardException {
    PhysicalCard card = new PhysicalCard();
    assertTrue("Reader initialization failed.", card.initialize());
    return card;
  }
}
