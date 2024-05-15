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
  byte TAG_TYPE;
  boolean TAG_EXTRACT_LOCKED;

  byte[] lastBuffer = new byte[256];
  byte[] lastResponse = new byte[256];
  byte[] NDEF_LastResponse = new byte[256];
  short NDEF_LastLength;
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
    boolean isNDEF_Read = (origin == (byte)0x03);
    boolean isNDEF_Write = (origin == (byte)0x01);
    boolean isFIDO = (origin == (byte)0x02);

    byte offsetOut = (byte)5;
    short outputLength = (short)0;

    if (isNDEF_Read) {
      Util.arrayCopy(NDEF_LastResponse, (short)0, buffer, (short)0, NDEF_LastLength);
      return NDEF_LastLength;
    }

    try {
      if (!INITIALIZED) initialize();
      outputLength = processTapDano(buffer, offsetIn, offsetOut);
    } catch (Exception e) {
      if (Constants.DEBUG) System.out.println("############### Exception ###############");
      outputLength = (short)1;
      buffer[offsetOut] = (byte)0x50;
    }

    if (isNDEF_Write) {
      buffer[0] = (byte)0x00;
      buffer[1] = (byte)(outputLength + 3);
      buffer[2] = (byte)0xD5;
      buffer[3] = (byte)0x00;
      buffer[4] = (byte)outputLength;
      outputLength += (short)5;
      Util.arrayCopy(buffer, (short)0, NDEF_LastResponse, (short)0, outputLength);
      NDEF_LastLength = outputLength;
    }

    if (isFIDO) {
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

    // Get Info
    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA0) {
      responseLen = getTagInfo(buffer, offsetIn, offsetOut, dataLen);
    }

    // Burn Tag
    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA1) {
      responseLen = burnTag(buffer, offsetIn, offsetOut, dataLen);
    }

    // Sign Data
    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA2) {
      responseLen = signData(buffer, offsetIn, offsetOut, dataLen);
    }

    // Format Tag
    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA3) {
      responseLen = formatTag(buffer, offsetIn, offsetOut, dataLen);
    }

    // Lock Tag
    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA4) {
      responseLen = lockTag(buffer, offsetIn, offsetOut, dataLen);
    }

    //INS not found
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
    SIGN_INITIALIZED = false;
    PAIR_GENERATED = false;
    priKeyEncoded = new byte[32];
    pubKeyEncoded = new byte[32];
  }

  private short getTagInfo(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    short responseLen = (short)0;
    buffer[offsetOut++] = (byte)0x54; // T[ap]
    buffer[offsetOut++] = (byte)0x44; // D[ano]
    buffer[offsetOut++] = (byte)0x01; // Version
    buffer[offsetOut++] = (byte)0x00; // Version
    buffer[offsetOut++] = PAIR_GENERATED ? (byte)0x01 : (byte)0x00;
    responseLen = (short)0x00005;
    if (PAIR_GENERATED) {
      boolean showPk = (TAG_TYPE == (byte)0x02) && (!TAG_EXTRACT_LOCKED);
      buffer[offsetOut++] = TAG_TYPE;
      buffer[offsetOut++] = TAG_EXTRACT_LOCKED ? (byte)0x01 : (byte)0x00;
      Util.arrayCopyNonAtomic(pubKeyEncoded, (short)0, buffer, (short)offsetOut, (short)pubKeyEncoded.length);
      offsetOut += (short)pubKeyEncoded.length;
      responseLen += (short)pubKeyEncoded.length + 2;
      if (showPk) {
        Util.arrayCopyNonAtomic(priKeyEncoded, (short)0, buffer, (short)offsetOut, (short)priKeyEncoded.length);
        offsetOut += (short)priKeyEncoded.length;
        responseLen += (short)priKeyEncoded.length;
      }
    }
    return responseLen;
  }

  private short burnTag(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    byte action = buffer[(short)(offsetIn + ISO7816.OFFSET_CDATA)];
    byte type = buffer[(short)(offsetIn + ISO7816.OFFSET_CDATA + 1)];
    byte[] importPrivateKey = new byte[32];

    if (PAIR_GENERATED) {
      return getTagInfo(buffer, offsetIn, offsetOut, dataLen);
    }
    
    if (action == (byte)0x02) { //restore
      if (type == (byte)0x01) { //soulbound
        buffer[offsetOut++] = (byte)0xEE;
        buffer[offsetOut++] = (byte)0x02;
        return (short)2;
      }
      Util.arrayCopyNonAtomic(buffer, (short)(offsetIn + ISO7816.OFFSET_CDATA + 2), importPrivateKey, (short)0, (short)importPrivateKey.length);
    }

    TAG_TYPE = type;
    TAG_EXTRACT_LOCKED = (type == (byte)0x01);

    if (action == (byte)0x01) { //new
      keypair.genKeyPair();
      prikey = (XECKey)keypair.getPrivate();
      pubkey = (XECKey)keypair.getPublic();
      prikey.getEncoded(priKeyEncoded, (short)0);
      pubkey.getEncoded(pubKeyEncoded, (short)0);
    }

    if (action == (byte)0x02) { //restore
      // TO DO
    }

    PAIR_GENERATED = true;

    return getTagInfo(buffer, offsetIn, offsetOut, dataLen);
  }

  public short signData(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) throws CryptoException {
    if (!SIGN_INITIALIZED) {
      signature.init((Key)prikey, Signature.MODE_SIGN);
      SIGN_INITIALIZED = true;
    }
    signature.sign(buffer, (short)(offsetIn + ISO7816.OFFSET_CDATA), dataLen, buffer, (short)offsetOut);
    return (short)64;
  }

  private short formatTag(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    initialize();
    return getTagInfo(buffer, offsetIn, offsetOut, dataLen);
  }

  private short lockTag(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    TAG_EXTRACT_LOCKED = true;
    return getTagInfo(buffer, offsetIn, offsetOut, dataLen);
  }
}