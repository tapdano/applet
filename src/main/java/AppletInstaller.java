package TapDano;

import javacard.framework.*;

public class AppletInstaller extends Applet {

  private AppletInstaller(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("AppletInstaller constructor");
  }

  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("AppletInstaller install");
    switch (buf[(short)(off + 1)]) {
      case (byte) 0x54:
        TapDanoApplet.install(buf, off, len);
        break;
      case (byte) 0xA0:
        FIDO2Applet.install(buf, off, len);
        break;
      case (byte) 0xD2:
        NDEFApplet.install(buf, off, len);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        break;
    }
  }

  public void process(APDU apdu) {
  }
}