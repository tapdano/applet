package tapdano;

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
      case (byte)0x89:
        if (Constants.DEBUG) System.out.println("### 0x89");
        AID TapDanoAID = new AID(Constants.TapDanoAIDBytes, (short)0, (byte)Constants.TapDanoAIDBytes.length);
        TapDanoShareable tapDano = (TapDanoShareable)JCSystem.getAppletShareableInterfaceObject(TapDanoAID, (byte)0x00);
        if (tapDano != null) {
          byte[] result = tapDano.exec((byte)0x02, buffer);
          apdu.setOutgoing();
          apdu.setOutgoingLength((short)result.length);
          apdu.sendBytesLong(result, (short)0, (short)result.length);
        }
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }
}