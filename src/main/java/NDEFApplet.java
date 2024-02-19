package TapDano;

import javacard.framework.*;

public class NDEFApplet extends Applet {

  private static final byte INS_SELECT  = ISO7816.INS_SELECT;
  final static byte INS_WRITE           = (byte) 0xD6;
  final static byte INS_READ            = (byte) 0xB0;

  private byte[] nfcData;

  protected NDEFApplet() {
    nfcData = new byte[256];
    if (Constants.DEBUG) System.out.println("NDEFApplet constructor");
  }

  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("NDEFApplet install");
    short pos = off;
    // find AID
    byte  lenAID = buf[pos++];
    short offAID = pos;
    new NDEFApplet().register(buf, offAID, lenAID);
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
      case (byte)0x78:
        if (Constants.DEBUG) System.out.println("### 0x78");
        break;
      case INS_SELECT:
        processSelect(apdu);
        break;
      case INS_WRITE:
        writeData(apdu);
        break;
      case INS_READ:
        readData(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  private void processSelect(APDU apdu) throws ISOException {
    apdu.setIncomingAndReceive();
  }

  private void writeData(APDU apdu) {
    if (Constants.DEBUG) System.out.println("writeData");
    byte[] buffer = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, nfcData, (short)0, bytesRead);
  }

  private void readData(APDU apdu) {
    if (Constants.DEBUG) System.out.println("readData");
    apdu.setOutgoing();
    apdu.setOutgoingLength((short)nfcData.length);
    apdu.sendBytesLong(nfcData, (short) 0, (short) nfcData.length);
  }
}