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

import java.util.Arrays;

/**
 * Simplified ASN-1 DER library (tag length = 1 or 2 bytes, length <= 0x3FFF)
 */
public class TLVDer {

  public enum Status {
    OK, END, ERROR
  }

  public int currentOffset;
  public int tag;
  public byte[] data;
  public Status status;

  TLVDer() {
    currentOffset = 0;
    tag = 0;
    data = null;
    status = Status.END;
  }

  public static TLVDer GetNext(byte[] data, int offset) {
    TLVDer tlv = new TLVDer();
    if (offset >= data.length) {
      return tlv;
    }
    tlv.currentOffset = offset;
    tlv.status = Status.ERROR;
    // Tag
    if ((data[offset] & 0x1F) == 0x1F) {
      // Two byte tag.
      // At length one byte for the length.
      if (data.length < offset + 3) {
        return tlv;
      }
      tlv.tag = (data[offset] & 0xFF) * 256 + (data[offset + 1] & 0xFF);
      if (tlv.tag > 0x7FFF) {
        // No support for 3 byte tags.
        return tlv;
      }
      tlv.currentOffset += 2;
    } else {
      // At length one byte for the length.
      if (data.length < offset + 2) {
        return tlv;
      }
      tlv.tag = data[offset] & 0xFF;
      tlv.currentOffset += 1;
    }
    // Length
    int dataLength;
    if (data[tlv.currentOffset] == (byte) 0x82) {
      if (data.length < tlv.currentOffset + 3) {
        return tlv;
      }
      dataLength = (data[tlv.currentOffset + 1] & 0xFF) * 256 +
                   (data[tlv.currentOffset + 2] & 0xFF);
      tlv.currentOffset += 3;
    } else if (data[tlv.currentOffset] == (byte) 0x81) {
      if (data.length < tlv.currentOffset + 2) {
        return tlv;
      }
      dataLength = data[tlv.currentOffset + 1] & 0xFF;
      tlv.currentOffset += 2;
    } else if ((data[tlv.currentOffset] & 0xFF) <= 0x7F) {
      dataLength = data[tlv.currentOffset] & 0x7F;
      tlv.currentOffset += 1;
    } else {
      return tlv;
    }
    if (data.length < tlv.currentOffset + dataLength) {
      return tlv;
    }
    tlv.status = Status.OK;
    tlv.data = Arrays.copyOfRange(data, tlv.currentOffset, tlv.currentOffset + dataLength);
    tlv.currentOffset += dataLength;
    return tlv;
  }

  /**
   * Create the Tag and Length fields according to the TLV DER rules.
   *
   * @param tag    is the raw tag that will go as-is in the encoding.
   * @param length must be < 16384
   * @return a byte array containing the encoded tag and length.
   */
  public static byte[] createTagLength(int tag, int length) throws IllegalArgumentException {
    if (tag > 0xFFFF || tag < 0 || length > 0x3FFF || length < 0) {
      throw new IllegalArgumentException("Invalid tag or length.");
    }
    int extraLength = (tag > 0xFF) ? 2 : 1;
    if (length > 255) {
      extraLength += 3;
    } else if (length > 127) {
      extraLength += 2;
    } else {
      extraLength += 1;
    }

    byte[] newData = new byte[extraLength];
    int pos;
    if (tag > 0xFF) {
      newData[0] = (byte) (tag / 256);
      newData[1] = (byte) (tag % 256);
      pos = 2;
    } else {
      pos = 1;
      newData[0] = (byte) (tag);
    }

    if (length > 255) {
      newData[pos] = (byte) 0x82;
      newData[pos + 1] = (byte) (length / 256);
      newData[pos + 2] = (byte) (length % 256);
      pos += 3;
    } else if (length > 127) {
      newData[pos] = (byte) 0x81;
      newData[pos + 1] = (byte) (length);
      pos += 2;
    } else {
      newData[pos] = (byte) (length);
    }
    return newData;
  }

  /**
   * Create a TLV encoded byte array encoded using the ASN-1 DER rules.
   *
   * @param tag  is the raw tag that will go as-is in the encoding.
   * @param data < 16384
   * @return a byte array containing the encoded TLV.
   */
  static public byte[] createTLVDER(int tag, byte[] data) throws IllegalArgumentException {
    if (tag > 0xFFFF || tag < 0 || data.length > 0x3FFF || data.length < 0) {
      throw new IllegalArgumentException("Invalid tag or length.");
    }
    byte[] tl = createTagLength(tag, data.length);
    byte[] newData = new byte[data.length + tl.length];
    System.arraycopy(tl, 0, newData, 0, tl.length);
    System.arraycopy(data, 0, newData, tl.length, data.length);
    return newData;
  }
}
