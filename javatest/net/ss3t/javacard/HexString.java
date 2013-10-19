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

import javax.xml.bind.DatatypeConverter;

/**
 */
public class HexString {


  final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

  public static String bytesToHex(byte[] bytes) {
    if (bytes.length == 0) {
      return "";
    }
    char[] hexChars = new char[2 + (bytes.length - 1) * 3];
    int v;
    int pos = 0;
    for (int j = 0; j < bytes.length; j++) {
      if (j > 0) {
        hexChars[pos++] = ' ';
      }
      v = bytes[j] & 0xFF;
      hexChars[pos++] = hexArray[v >>> 4];
      hexChars[pos++] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static byte[] toByteArray(String s) {
    return DatatypeConverter.parseHexBinary(s.replaceAll("\\s+", ""));
  }

  /**
   * Concatenates byte arrays.
   *
   * @param arrays the arrays to concatenate.
   * @return the concatenation of the arrays passed in.
   */
  static public byte[] mergeByteArrays(byte[]... arrays) {
    int len = 0;
    for (byte[] a : arrays) {
      len += a.length;
    }
    byte[] merged = new byte[len];
    int pos = 0;
    for (byte[] a : arrays) {
      System.arraycopy(a, 0, merged, pos, a.length);
      pos += a.length;
    }
    return merged;
  }
}
