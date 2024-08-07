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
  boolean PIN_LOCKED;
  byte[] PIN = new byte[4];

  byte[] lastBuffer = new byte[256];
  byte[] lastResponse = new byte[256];
  byte[] POLICY_ID = new byte[28];
  byte[] TWO_FACTOR_KEY = new byte[32];
  byte[] LAST_SIGNATURE = new byte[64];

  short lastResponseLen;

  byte[] dataToHash = new byte[33];
  byte[] inputPin = new byte[4];

  NamedParameterSpec params;
  XECKey prikey;
  XECKey pubkey;
  KeyPair keypair;
  Signature signature;
  MessageDigest sha256;

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
      short outputLength = processTapDano(buffer, (byte) 0, (byte) 0);
      apdu.setOutgoingAndSend((short) 0, outputLength);
    } catch (Exception e) {
      ISOException.throwIt((short) 0xFF01);
    }
  }

  public short exec(byte origin, byte[] buffer, byte offsetIn) {
    boolean isNDEF_Read = (origin == (byte) 0x03);
    boolean isNDEF_Write = (origin == (byte) 0x01);
    boolean isFIDO = (origin == (byte) 0x02);

    byte offsetOut = (byte) 5;
    short outputLength = (short) 0;

    try {
      if (!INITIALIZED) initialize();
      outputLength = processTapDano(buffer, offsetIn, offsetOut);
    } catch (Exception e) {
      if (Constants.DEBUG) System.out.println("############### Exception ###############");
      outputLength = (short) 1;
      buffer[offsetOut] = (byte) 0x50;
    }

    if (isNDEF_Read || isNDEF_Write) {
      buffer[0] = (byte) 0x00;
      buffer[1] = (byte) (outputLength + 3);
      buffer[2] = (byte) 0xD5;
      buffer[3] = (byte) 0x00;
      buffer[4] = (byte) outputLength;
      outputLength += (short) 5;
    }

    if (isFIDO) {
      outputLength += (byte) 5;
      buffer[0] = (byte) 0x01;
      buffer[1] = (byte) 0x00;
      buffer[2] = (byte) 0x00;
      buffer[3] = (byte) 0x00;
      buffer[4] = (byte) 0x01;
    }

    return outputLength;
  }

  public short processTapDano(byte[] buffer, byte offsetIn, byte offsetOut) {
    short dataLen = (short) buffer[(byte) (offsetIn + ISO7816.OFFSET_LC)];

    // Burn Tag
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA1) {
      burnTag(buffer, offsetIn, offsetOut, dataLen);
    }

    // Sign Data
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA2) {
      signData(buffer, offsetIn, offsetOut, dataLen);
    }

    // Format Tag
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA3) {
      formatTag(buffer, offsetIn, offsetOut, dataLen);
    }

    // Lock Tag
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA4) {
      lockTag(buffer, offsetIn, offsetOut, dataLen);
    }

    // Pin Lock
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA5) {
      pinLock(buffer, offsetIn, offsetOut, dataLen);
    }

    // Pin Unlock
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA6) {
      pinUnlock(buffer, offsetIn, offsetOut, dataLen);
    }

    // Set PolicyId
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xA7) {
      setPolicyId(buffer, offsetIn, offsetOut, dataLen);
    }

    // Get Memory
    if (buffer[(byte) (offsetIn + ISO7816.OFFSET_INS)] == (byte) 0xB0) {
      Util.setShort(buffer, (short)offsetOut, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
      Util.setShort(buffer, (short)(offsetOut + (byte)0x02), JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
      return (short)0x0004;
    }

    short responseLen = getTagInfo(buffer, offsetIn, offsetOut, dataLen);

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

    keypair = new KeyPair((PublicKey) pubkey, (PrivateKey) prikey);

    signature = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA, Cipher.PAD_NULL, false);

    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    INITIALIZED = true;
    SIGN_INITIALIZED = false;
    PAIR_GENERATED = false;
    Util.arrayFillNonAtomic(priKeyEncoded, (short) 0, (short) priKeyEncoded.length, (byte) 0);
    Util.arrayFillNonAtomic(pubKeyEncoded, (short) 0, (short) pubKeyEncoded.length, (byte) 0);
    Util.arrayFillNonAtomic(POLICY_ID, (short) 0, (short) POLICY_ID.length, (byte) 0);
    Util.arrayFillNonAtomic(TWO_FACTOR_KEY, (short) 0, (short) TWO_FACTOR_KEY.length, (byte) 0);
    Util.arrayFillNonAtomic(LAST_SIGNATURE, (short) 0, (short) LAST_SIGNATURE.length, (byte) 0);
  }

  private short getTagInfo(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    short responseLen = (short) 0;
    buffer[offsetOut++] = (byte) 0x54; // T[ap]
    buffer[offsetOut++] = (byte) 0x44; // D[ano]
    buffer[offsetOut++] = (byte) 0x01; // Version
    buffer[offsetOut++] = (byte) 0x01; // Version
    buffer[offsetOut++] = PAIR_GENERATED ? (byte) 0x01 : (byte) 0x00;
    responseLen = (short) 0x00005;
    if (PAIR_GENERATED) {
      buffer[offsetOut++] = TAG_TYPE;
      buffer[offsetOut++] = TAG_EXTRACT_LOCKED ? (byte) 0x01 : (byte) 0x00;
      buffer[offsetOut++] = PIN_LOCKED ? (byte) 0x01 : (byte) 0x00;
      responseLen += 3;

      boolean showPk = (TAG_TYPE == (byte) 0x02) && (!TAG_EXTRACT_LOCKED) && (!PIN_LOCKED);
      Util.arrayCopyNonAtomic(showPk ? priKeyEncoded : pubKeyEncoded, (short) 0, buffer, (short) offsetOut, (short) 32);
      offsetOut += (short) 32;
      responseLen += (short) 32;

      Util.arrayCopyNonAtomic(POLICY_ID, (short) 0, buffer, (short) offsetOut, (short) POLICY_ID.length);
      offsetOut += (short) POLICY_ID.length;
      responseLen += (short) POLICY_ID.length;

      if (!PIN_LOCKED) {
        Util.arrayCopyNonAtomic(TWO_FACTOR_KEY, (short) 0, buffer, (short) offsetOut, (short) TWO_FACTOR_KEY.length);
        offsetOut += (short) TWO_FACTOR_KEY.length;
        responseLen += (short) TWO_FACTOR_KEY.length;

        Util.arrayCopyNonAtomic(LAST_SIGNATURE, (short) 0, buffer, (short) offsetOut, (short) LAST_SIGNATURE.length);
        offsetOut += (short) LAST_SIGNATURE.length;
        responseLen += (short) LAST_SIGNATURE.length;
      }
    }
    return responseLen;
  }

  private void burnTag(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    byte action = buffer[(short) (offsetIn + ISO7816.OFFSET_CDATA)];
    byte type = buffer[(short) (offsetIn + ISO7816.OFFSET_CDATA + 1)];

    if (PAIR_GENERATED) return;

    if (action == (byte) 0x02) { // restore
      if (type == (byte) 0x01) { // soulbound
        return;
      }
    }

    TAG_TYPE = type;
    TAG_EXTRACT_LOCKED = (type == (byte) 0x01);
    PIN_LOCKED = false;

    if (action == (byte) 0x01) { // new
      keypair.genKeyPair();
      prikey = (XECKey) keypair.getPrivate();
      pubkey = (XECKey) keypair.getPublic();
      prikey.getEncoded(priKeyEncoded, (short) 0);
      pubkey.getEncoded(pubKeyEncoded, (short) 0);
    }

    if (action == (byte) 0x02) { // restore
      prikey.setEncoded(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 2), (short) priKeyEncoded.length);
      pubkey.setEncoded(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 34), (short) pubKeyEncoded.length);
      Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 2), priKeyEncoded, (short) 0, (short) priKeyEncoded.length);
      Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 34), pubKeyEncoded, (short) 0, (short) pubKeyEncoded.length);
    }

    // TWO_FACTOR_KEY
    Util.arrayCopyNonAtomic(priKeyEncoded, (short) 0, dataToHash, (short) 0, (short) 32);
    dataToHash[32] = (byte) 0x01;
    sha256.doFinal(dataToHash, (short) 0, (short) dataToHash.length, TWO_FACTOR_KEY, (short) 0);

    PAIR_GENERATED = true;
  }

  public void signData(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) throws CryptoException {
    if (!SIGN_INITIALIZED) {
      signature.init((Key) prikey, Signature.MODE_SIGN);
      SIGN_INITIALIZED = true;
    }
    signature.sign(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), dataLen, LAST_SIGNATURE, (short) 0);
  }

  private void formatTag(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    initialize();
  }

  private void lockTag(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    TAG_EXTRACT_LOCKED = true;
  }

  private void pinLock(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), PIN, (short) 0, (short) PIN.length);
    PIN_LOCKED = true;
  }

  private void pinUnlock(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), inputPin, (short) 0, (short) inputPin.length);
    if (Util.arrayCompare(inputPin, (short) 0, PIN, (short) 0, (short) PIN.length) == 0) {
      PIN_LOCKED = false;
    }
  }

  private void setPolicyId(byte[] buffer, byte offsetIn, byte offsetOut, short dataLen) {
    Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), POLICY_ID, (short) 0, (short) POLICY_ID.length);
  }
}