package TapDano;

import javacard.framework.*;

public class FIDO2Applet extends Applet {

  protected FIDO2Applet() {
    if (Constants.DEBUG) System.out.println("FIDO2Applet constructor");
  }

  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("FIDO2Applet install");
    short pos = off;
    // find AID
    byte  lenAID = buf[pos++];
    short offAID = pos;
    new FIDO2Applet().register(buf, offAID, lenAID);
  }

  public boolean select() {
    return true;
  }

  public void process(APDU apdu) {
    if (selectingApplet()) return;

    byte[] buffer = apdu.getBuffer();
    byte cla = buffer[ISO7816.OFFSET_CLA];
    byte ins = buffer[ISO7816.OFFSET_INS];

    switch (ins) {
      case (byte)0x79:
        if (Constants.DEBUG) System.out.println("### 0x79");
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }
}