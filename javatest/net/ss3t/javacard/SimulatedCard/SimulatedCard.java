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

package net.ss3t.javacard.SimulatedCard;

import com.licel.jcardsim.base.Simulator;

import net.ss3t.javacard.CardInterface;

import java.util.logging.Logger;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.framework.AID;

/**
 * Uses the jcardSim classes
 */
public class SimulatedCard implements CardInterface {

  private Simulator simulator = null;
  protected static final Logger logger = Logger.getLogger("Simulated Card");

  public boolean initialize(byte[] aid, Class applet) {
    simulator = new Simulator();
    simulator.resetRuntime();
    AID appletAID = new AID(aid, (short) 0, (byte) aid.length);
    simulator.installApplet(appletAID, applet);
    return true;
  }

  @Override
  public void reset() throws CardException {
    simulator.reset();
  }

  @Override
  public boolean selectApplet(byte[] aid) throws CardException {
    return simulator.selectApplet(new AID(aid, (short) 0, (byte) aid.length));
  }

  @Override
  public ResponseAPDU sendAPDU(CommandAPDU command) throws CardException {
    return new ResponseAPDU(simulator.transmitCommand(command.getBytes()));
  }
}
