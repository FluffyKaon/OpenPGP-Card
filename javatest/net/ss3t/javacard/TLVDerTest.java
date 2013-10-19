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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static net.ss3t.javacard.HexString.mergeByteArrays;
import static net.ss3t.javacard.HexString.toByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 */
@RunWith(JUnit4.class)
public class TLVDerTest {

  @Test
  public void singleByteTag() {
    TLVDer t = TLVDer.GetNext(toByteArray("4D 01 02"), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(3, t.currentOffset);
    assertEquals(0x4D, t.tag);
    assertArrayEquals(toByteArray("02"), t.data);

    // No data
    t = TLVDer.GetNext(toByteArray("4D 00"), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(2, t.currentOffset);
    assertEquals(0x4D, t.tag);
    assertArrayEquals(toByteArray(""), t.data);

    // 2 byte length
    t = TLVDer.GetNext(mergeByteArrays(toByteArray("4D 81 80"), new byte[128]), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(131, t.currentOffset);
    assertEquals(0x4D, t.tag);
    assertArrayEquals(new byte[128], t.data);
    // 3 byte length
    t = TLVDer.GetNext(mergeByteArrays(toByteArray("4D 82 01 02"), new byte[258]), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(262, t.currentOffset);
    assertEquals(0x4D, t.tag);
    assertArrayEquals(new byte[258], t.data);

    // Error conditions.
    t = TLVDer.GetNext(toByteArray("4D 01"), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);
    // Not enough data.
    t = TLVDer.GetNext(toByteArray("4D 02 03"), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);
    // Too short
    t = TLVDer.GetNext(toByteArray("4D"), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);

    // Incomplete tag
    t = TLVDer.GetNext(toByteArray("7F"), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);
    // Invalid length
    t = TLVDer.GetNext(mergeByteArrays(toByteArray("4D 83 00 00"), new byte[65536]), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);
    // Incomplete length
    t = TLVDer.GetNext(toByteArray("4D 81"), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);

    t = TLVDer.GetNext(toByteArray("4D 82 00"), 0);
    assertEquals(TLVDer.Status.ERROR, t.status);
  }

  @Test
  public void twoByteTag() {
    TLVDer t = TLVDer.GetNext(toByteArray("7F48 01 02"), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(4, t.currentOffset);
    assertEquals(0x7F48, t.tag);
    assertArrayEquals(toByteArray("02"), t.data);

    // No data
    t = TLVDer.GetNext(toByteArray("7F48 00"), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(3, t.currentOffset);
    assertEquals(0x7F48, t.tag);
    assertArrayEquals(toByteArray(""), t.data);

    // 2 byte length
    t = TLVDer.GetNext(mergeByteArrays(toByteArray("7F48 81 80"), new byte[128]), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(132, t.currentOffset);
    assertEquals(0x7F48, t.tag);
    assertArrayEquals(new byte[128], t.data);
    // 3 byte length
    t = TLVDer.GetNext(mergeByteArrays(toByteArray("7F48 82 01 02"), new byte[258]), 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(263, t.currentOffset);
    assertEquals(0x7F48, t.tag);
    assertArrayEquals(new byte[258], t.data);

  }

  @Test
  public void chaining() {
    byte[] data = toByteArray("4D 01 02 60 03 04 05 06");
    TLVDer t = TLVDer.GetNext(data, 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(0x4D, t.tag);
    assertArrayEquals(toByteArray("02"), t.data);
    t = TLVDer.GetNext(data, t.currentOffset);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(0x60, t.tag);
    assertArrayEquals(toByteArray("04 05 06"), t.data);
    t = TLVDer.GetNext(data, t.currentOffset);
    assertEquals(TLVDer.Status.END, t.status);

    data = toByteArray("4D 01 02 7F60 03 04 05 06");
    t = TLVDer.GetNext(data, 0);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(0x4D, t.tag);
    assertArrayEquals(toByteArray("02"), t.data);
    t = TLVDer.GetNext(data, t.currentOffset);
    assertEquals(TLVDer.Status.OK, t.status);
    assertEquals(0x7F60, t.tag);
    assertArrayEquals(toByteArray("04 05 06"), t.data);
    t = TLVDer.GetNext(data, t.currentOffset);
    assertEquals(TLVDer.Status.END, t.status);

  }
}
