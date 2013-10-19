package net.ss3t.javacard.PhysicalCard;

import net.sourceforge.gpj.cardservices.AID;
import net.sourceforge.gpj.cardservices.APDUListener;
import net.sourceforge.gpj.cardservices.GlobalPlatformService;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static net.ss3t.javacard.CardUtils.formatCommandAPDU;
import static net.ss3t.javacard.CardUtils.formatResponseAPDU;

/**
 * Allows the applet to be reloaded on a real Global Platform card.
 * Tested on a development J2A080 NXP card ( JCOP 2.4.1, JC 2.2.2, GP 2.1.1 ).
 * This code is heavily dependent on the card used:
 * - the 40....4F test keys are used without derivation.
 * - the secure channel version.
 */
public class GlobalPlatformCard extends PhysicalCard implements APDUListener {
  @Override
  public void exchangedAPDU(CommandAPDU c, ResponseAPDU r) {
    logger.info(formatCommandAPDU(c));
    logger.info(formatResponseAPDU(r));
  }
  int keySet = 0;
  private byte[] packageAID;
  public static byte[] opSecurityDomainAID = {(byte)0xA0, 0, 0, 0, 3, 0, 0, 0};

  static byte installPrivileges = 0;
  static byte[] installParams = null;

  public GlobalPlatformCard(byte[] packageAID) {
    this.packageAID = packageAID;
  }

  private ResponseAPDU loggedAPDU(CommandAPDU apdu)  throws CardException {
    logger.info(formatCommandAPDU(apdu));
    ResponseAPDU r = sendAPDU(apdu);
    logger.info(formatResponseAPDU(r));
    return r;
  }

  @Override
  public boolean reinstallApplet(byte[] aid) throws CardException {
    logger.info("[Reinstalling the applet]");
    int keySet = 0;
    byte[][] keys = { GlobalPlatformService.defaultEncKey, GlobalPlatformService.defaultMacKey,
                      GlobalPlatformService.defaultKekKey };

    GlobalPlatformService service = new GlobalPlatformService(
        new AID(opSecurityDomainAID), channel);

    service.addAPDUListener(this);
    service.open();
    service.setKeys(keySet, GlobalPlatformService.defaultEncKey,
                    GlobalPlatformService.defaultMacKey, GlobalPlatformService.defaultKekKey,
                    GlobalPlatformService.DIVER_NONE);

    service.openSecureChannel(keySet, 0,
                              GlobalPlatformService.SCP_ANY,
                              GlobalPlatformService.APDU_MAC, false);

    service.deleteAID(new AID(aid), true);
    service.installAndMakeSelecatable(new AID(packageAID), new AID(aid), new AID(aid),
                                      installPrivileges, installParams, null);

    return loggedAPDU(new CommandAPDU(0, 0xA4, 4, 0, aid)).getSW() == 0x9000;
  }

}
