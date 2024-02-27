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
    byte lenAID = buf[pos++];
    short offAID = pos;
    new FIDO2Applet().register(buf, offAID, lenAID);
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      byte[] U2F_V2_RESPONSE = { 0x55, 0x32, 0x46, 0x5F, 0x56, 0x32 }; // U2F_V2
      sendByteArray(apdu, U2F_V2_RESPONSE);
      return;
    }

    byte[] buffer = apdu.getBuffer();
    
    if (buffer[ISO7816.OFFSET_CLA] == (byte)0x80) ISOException.throwIt((short)0x6D00);

    if ((buffer[ISO7816.OFFSET_CLA] == (byte)0x00) && (buffer[ISO7816.OFFSET_INS] == (byte)0x02) && (buffer[ISO7816.OFFSET_P1] == (byte)0x07)) ISOException.throwIt((short)0x6985);

    if ((buffer[ISO7816.OFFSET_CLA] == (byte)0x00) && (buffer[ISO7816.OFFSET_INS] == (byte)0x02) && (buffer[ISO7816.OFFSET_P1] == (byte)0x03)) {
      AID TapDanoAID = new AID(Constants.TapDanoAIDBytes, (short)0, (byte)Constants.TapDanoAIDBytes.length);
      TapDanoShareable tapDano = (TapDanoShareable)JCSystem.getAppletShareableInterfaceObject(TapDanoAID, (byte)0x00);
      if (tapDano != null) {
        byte[] result = tapDano.exec((byte)0x02, buffer, (short)(ISO7816.OFFSET_CDATA + 65), (short)buffer[ISO7816.OFFSET_CDATA + 64]);
        byte[] apduResponse = new byte[(byte)(result.length + 5)];
        apduResponse[0] = (byte)0x01;
        apduResponse[4] = (byte)0x01;
        Util.arrayCopyNonAtomic(result, (short)0, apduResponse, (short)5, (short)result.length);
        sendByteArray(apdu, apduResponse);
        return;        
      }
    }

    ISOException.throwIt(ISO7816.SW_UNKNOWN);
  }

  private static void sendByteArray(APDU apdu, byte[] array) {
    byte[] buffer = apdu.getBuffer();
    Util.arrayCopyNonAtomic(array, (short)0, buffer, (short)0, (short)array.length);
    apdu.setOutgoingAndSend((short) 0, (short)array.length);
  }
}