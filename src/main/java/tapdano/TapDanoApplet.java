package tapdano;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class TapDanoApplet extends Applet implements TapDanoShareable {

  boolean INITIALIZED = false;
  boolean PAIR_GENERATED = false;
  boolean SIGN_INITIALIZED = false;
  byte[] priKeyEncoded = new byte[32];
  byte[] pubKeyEncoded = new byte[32];
  byte[] lastBuffer = new byte[256];
  byte[] lastResponse = new byte[256];
  short lastResponseLen;

  NamedParameterSpec params;
  XECKey prikey;
  XECKey pubkey;
  KeyPair keypair;
  Signature signature;

  protected TapDanoApplet(byte[] buf, short offAID, byte lenAID) {
    if (Constants.DEBUG) System.out.println("TapDanoApplet constructor");
    register(buf, offAID, lenAID);
  }

  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("TapDanoApplet install");
    short pos = off;
    // find AID
    byte lenAID = buf[pos++];
    short offAID = pos;
    new TapDanoApplet(buf, offAID, lenAID);
  }

  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    return this;
  }

  public boolean select() {
    return true;
  }

  public void process(APDU apdu) {
    if (!INITIALIZED) initialize();
    if (selectingApplet()) return;
    byte[] buffer = apdu.getBuffer();
    try {
      short outputLength = processTapDano(buffer, (byte)0, (byte)0);
      apdu.setOutgoingAndSend((short)0, outputLength);
    } catch (Exception e) {
      ISOException.throwIt((short)0xFF01);
    }
  }

  public short exec(byte origin, byte[] buffer, byte offsetIn) {
    byte offsetOut = (origin == (byte)0x02) ? (byte)5 : (byte)0;
    short outputLength = (short)0;
    try {
      if (!INITIALIZED) initialize();
      outputLength = processTapDano(buffer, offsetIn, offsetOut);
    } catch (Exception e) {
      if (Constants.DEBUG) System.out.println("############### Exception ###############");
      outputLength = (short)1;
      buffer[offsetOut] = (byte)0x50;
    }
    if (origin == (byte)0x02) {
      outputLength += (byte)5;
      buffer[0] = (byte)0x01;
      buffer[1] = (byte)0x00;
      buffer[2] = (byte)0x00;
      buffer[3] = (byte)0x00;
      buffer[4] = (byte)0x01;
    }
    return outputLength;
  }

  public short processTapDano(byte[] buffer, byte offsetIn, byte offsetOut) {
    short dataLen = (short)buffer[(byte)(offsetIn + ISO7816.OFFSET_LC)];
    byte offsetOutOriginal = offsetOut;

    boolean isCacheActive = (buffer[(byte)(offsetIn + ISO7816.OFFSET_P1)] == (byte)0x01);
    byte[] lastBufferTemp = new byte[256];

    if (isCacheActive) {
      if (Util.arrayCompare(buffer, (short)offsetIn, lastBuffer, (short)0, (short)(256 - offsetIn)) == (byte)0) {
        Util.arrayCopy(lastResponse, (short)0, buffer, (short)offsetOut, (short)(256 - offsetOut));
        return lastResponseLen;
      }
      dataLen = (short)(dataLen - 8);
      Util.arrayCopy(buffer, (short)offsetIn, lastBufferTemp, (short)0, (short)(256 - offsetIn));
    }

    short responseLen = (short)0;

    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA0) {
      buffer[offsetOut++] = (byte)0x01;
      buffer[offsetOut++] = (byte)0x00;
      responseLen = (short)2;
    }

    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA1) {
      responseLen = generateKeypair(buffer, offsetIn, offsetOut);
    }

    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA2) {
      responseLen = signData(buffer, offsetIn, offsetOut, dataLen);
    }

    if (responseLen == (short)0) {
      buffer[offsetOut++] = (byte)0x6D;
      buffer[offsetOut++] = (byte)0x00;
      responseLen = (short)2;
    }

    if (isCacheActive) {
      lastResponseLen = responseLen;
      Util.arrayCopy(lastBufferTemp, (short)0, lastBuffer, (short)0, (short)lastBuffer.length);
      Util.arrayCopy(buffer, (short)offsetOutOriginal, lastResponse, (short)0, (short)(256 - offsetOutOriginal));
    }

    return responseLen;
  }

  private void initialize() {
    params = NamedParameterSpec.getInstance(NamedParameterSpec.ED25519);

    short attributes = KeyBuilder.ATTR_PRIVATE;
    attributes |= JCSystem.MEMORY_TYPE_PERSISTENT;
    prikey = (XECKey) KeyBuilder.buildXECKey(params, attributes, false);

    attributes = KeyBuilder.ATTR_PUBLIC;
    attributes |= JCSystem.MEMORY_TYPE_PERSISTENT;
    pubkey = (XECKey) KeyBuilder.buildXECKey(params, attributes, false);

    keypair = new KeyPair((PublicKey)pubkey,(PrivateKey)prikey);

    signature = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA, Cipher.PAD_NULL, false);

    INITIALIZED = true;
  }

  private short generateKeypair(byte[] buffer, byte offsetIn, byte offsetOut) {
    if (!PAIR_GENERATED) {
      keypair.genKeyPair();

      prikey = (XECKey)keypair.getPrivate();
      pubkey = (XECKey)keypair.getPublic();

      prikey.getEncoded(priKeyEncoded, (short)0);
      pubkey.getEncoded(pubKeyEncoded, (short)0);

      //PAIR_GENERATED = true;
    }

    Util.arrayCopyNonAtomic(priKeyEncoded, (short)0, buffer, (short)offsetOut, (short)priKeyEncoded.length);
    Util.arrayCopyNonAtomic(pubKeyEncoded, (short)0, buffer, (short)(offsetOut + priKeyEncoded.length), (short)pubKeyEncoded.length);

    return (short)(priKeyEncoded.length + pubKeyEncoded.length);
  }

  public short signData(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) throws CryptoException {
    if (!SIGN_INITIALIZED) {
      signature.init((Key)prikey, Signature.MODE_SIGN);
      SIGN_INITIALIZED = true;
    }
    signature.sign(buffer, (short)(offsetIn + ISO7816.OFFSET_CDATA), dataLen, buffer, (short)offsetOut);
    return (short)64;
  }
}