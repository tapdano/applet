package TapDano;

import javacard.framework.*;

public class TapDano extends Applet {
  private static final boolean DEBUG = false;

  protected TapDano() {
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new TapDano().register();
  }

  public boolean select() {
    return true;
  }

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    byte[] buffer = apdu.getBuffer();
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
  }
}