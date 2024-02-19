package TapDano;

import javacard.framework.*;

public class TapDanoApplet extends Applet implements TapDanoShareable {

  protected TapDanoApplet() {
    if (Constants.DEBUG) System.out.println("TapDanoApplet constructor");
  }

  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("TapDanoApplet install");
    short pos = off;
    // find AID
    byte  lenAID = buf[pos++];
    short offAID = pos;
    new TapDanoApplet().register(buf, offAID, lenAID);
  }

  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
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
      case (byte)0x77:
      if (Constants.DEBUG) System.out.println("### 0x77");
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    /*
    short bytesRead = apdu.setIncomingAndReceive();

    if (DEBUG) {
      StringBuilder sb = new StringBuilder();
      for (short i = 0; i < buffer.length; i++) {
          sb.append(String.format("%02X ", buffer[i]));
      }
      System.out.println(sb.toString());

      System.out.println("buffer.length");
      System.out.println(buffer.length);

      System.out.println("bytesRead");
      System.out.println(bytesRead);

      System.out.println("ISO7816.OFFSET_CDATA");
      System.out.println(ISO7816.OFFSET_CDATA);
    }

    apdu.setOutgoing();
    apdu.setOutgoingLength(bytesRead);
    apdu.sendBytes(ISO7816.OFFSET_CDATA, bytesRead);
    */
  }

  public byte[] exec(byte origin, byte[] buf) {
    if (Constants.DEBUG) System.out.println("TapDanoApplet - exec (origin = " + origin + ")");
    byte[] result = new byte[1];
    result[0] = (byte)0x01;
    if (origin == (byte)1) {
      result[0] = (byte)0x05;
    }
    if (origin == (byte)2) {
      result[0] = (byte)0x06;
    }
    return result;
  }
}