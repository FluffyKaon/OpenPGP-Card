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

import java.util.HashMap;
import java.util.Map;

enum Access {
  ALWAYS, NEVER, PW1, PW3
}

enum DataObject {
  PRIVATE_USE_1(0x101, 0, 254, Access.ALWAYS, Access.PW1),
  PRIVATE_USE_2(0x102, 0, 254, Access.ALWAYS, Access.PW3),
  PRIVATE_USE_3(0x103, 0, 254, Access.PW1, Access.PW1),
  PRIVATE_USE_4(0x104, 0, 254, Access.PW3, Access.PW3),
  AID(0x4F, 0, 16, Access.ALWAYS, Access.NEVER),
  LOGIN(0x5E, 0, 254, Access.ALWAYS, Access.PW3),
  NAME(0x5B, 0, 39, Access.ALWAYS, Access.PW3),
  LANGUAGE_PREFERENCE(0x5F2D, 0, 8, Access.ALWAYS, Access.PW3),
  SEX(0x5F35, 1, 1, Access.ALWAYS, Access.PW3),
  HISTORICAL_BYTES(0x5F52, 0, 0, Access.ALWAYS, Access.NEVER),
  SIGNATURE_COUNTER(0x93, 3, 3, Access.ALWAYS, Access.NEVER),
  DISCRETIONARY_DOS(0x73, 0, 0, Access.ALWAYS, Access.NEVER),
  CARDHOLDER_RELATED_DATA(0x65, 0, 0, Access.ALWAYS, Access.NEVER),
  EXTENDED_CAPABILITIES(0xC0, 0, 0, Access.ALWAYS, Access.NEVER),
  ALGORITHM_ATTRIBUTES_1(0xC1, 6, 6, Access.ALWAYS, Access.NEVER), // Special.
  ALGORITHM_ATTRIBUTES_2(0xC2, 6, 6, Access.ALWAYS, Access.NEVER), // Special.
  ALGORITHM_ATTRIBUTES_3(0xC3, 6, 6, Access.ALWAYS, Access.NEVER), // Special.
  FINGERPRINTS(0xC5, 60, 60, Access.ALWAYS, Access.NEVER),
  CA_FINGERPRINTS(0xC6, 60, 60, Access.ALWAYS, Access.NEVER),
  FINGERPRINT_1(0xC7, 20, 20, Access.NEVER, Access.PW3, true),
  FINGERPRINT_2(0xC8, 20, 20, Access.NEVER, Access.PW3, true),
  FINGERPRINT_3(0xC9, 20, 20, Access.NEVER, Access.PW3, true),
  CA_FINGERPRINT_1(0xCA, 20, 20, Access.NEVER, Access.PW3, true),
  CA_FINGERPRINT_2(0xCB, 20, 20, Access.NEVER, Access.PW3, true),
  CA_FINGERPRINT_3(0xCC, 20, 20, Access.NEVER, Access.PW3, true),
  GENERATION_TIMES(0xCD, 12, 12, Access.ALWAYS, Access.NEVER),
  GENERATION_TIME_1(0xCE, 4, 4, Access.NEVER, Access.PW3, true),
  GENERATION_TIME_2(0xCF, 4, 4, Access.NEVER, Access.PW3, true),
  GENERATION_TIME_3(0xD0, 4, 4, Access.NEVER, Access.PW3, true),
  APPLICATION_RELATED_DATA(0x6E, 0, 0, Access.ALWAYS, Access.NEVER, false),
  PW_STATUS(0xC4, 7, 7, Access.ALWAYS, Access.NEVER); // Special

  public final int tag;
  public final int minLength;
  public final int maxLength;
  public final Access readAccess;
  public final Access writeAccess;
  // This means that the object is only read as part of a set but written individually.
  public final boolean groupedRead;

  private static final Map<Integer, DataObject> mapByTag = new HashMap<>();

  static {
    for (DataObject data : DataObject.values()) {
      mapByTag.put(data.tag, data);
    }
  }

  DataObject(int tag, int minLength, int maxLength, Access readAccess, Access writeAccess) {
    this.tag = tag;
    this.minLength = minLength;
    this.maxLength = maxLength;
    this.readAccess = readAccess;
    this.writeAccess = writeAccess;
    this.groupedRead = false;
  }

  DataObject(int tag, int minLength, int maxLength, Access readAccess, Access writeAccess,
             boolean groupedRead) {
    this.tag = tag;
    this.minLength = minLength;
    this.maxLength = maxLength;
    this.readAccess = readAccess;
    this.writeAccess = writeAccess;
    this.groupedRead = groupedRead;
  }

  public static DataObject getByTag(int tag) {
    return mapByTag.get(tag);
  }
}
