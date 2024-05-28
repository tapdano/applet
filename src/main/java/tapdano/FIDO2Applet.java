package tapdano;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

public class FIDO2Applet extends Applet implements ExtendedLength {

  protected FIDO2Applet() {
    if (Constants.DEBUG) System.out.println("FIDO2Applet constructor");
  }

  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("FIDO2Applet install");
    short pos = off;
    byte lenAID = buf[pos++];
    short offAID = pos;
    new FIDO2Applet().register(buf, offAID, lenAID);
  }

  public void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    if (selectingApplet()) {
      buffer[0] = (byte)0x55; //U
      buffer[1] = (byte)0x32; //2
      buffer[2] = (byte)0x46; //F
      buffer[3] = (byte)0x5F; //_
      buffer[4] = (byte)0x56; //V
      buffer[5] = (byte)0x32; //2
      apdu.setOutgoingAndSend((short)0, (short)6);
      return;
    }

    boolean extendedAPDU = (buffer[ISO7816.OFFSET_LC] == (byte)0x00) && ((buffer[ISO7816.OFFSET_LC + 1] != (byte)0x00) || (buffer[ISO7816.OFFSET_LC + 2] != (byte)0x00));

    if (buffer[ISO7816.OFFSET_CLA] == (byte)0x80) {
      ISOException.throwIt((short)0x6D00);
      return;
    }

    if ((buffer[ISO7816.OFFSET_CLA] == (byte)0x00) && (buffer[ISO7816.OFFSET_INS] == (byte)0x02) && (buffer[ISO7816.OFFSET_P1] == (byte)0x07)) {
      ISOException.throwIt((short)0x6985);
      return;
    }

    if ((buffer[ISO7816.OFFSET_CLA] == (byte)0x00) && (buffer[ISO7816.OFFSET_INS] == (byte)0x02) && (buffer[ISO7816.OFFSET_P1] == (byte)0x03)) {
      AID TapDanoAID = new AID(Constants.TapDanoAIDBytes, (short)0, (byte)Constants.TapDanoAIDBytes.length);
      TapDanoShareable tapDano = (TapDanoShareable)JCSystem.getAppletShareableInterfaceObject(TapDanoAID, (byte)0x00);
      if (tapDano != null) {
        short outputLength = tapDano.exec((byte)0x02, buffer, (byte)((extendedAPDU ? ISO7816.OFFSET_EXT_CDATA : ISO7816.OFFSET_CDATA) + 65));
        apdu.setOutgoingAndSend((short)0, outputLength);
        return;
      }
    }

    ISOException.throwIt(ISO7816.SW_UNKNOWN);
  }
}