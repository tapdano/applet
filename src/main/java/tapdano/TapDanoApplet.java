package tapdano;

import javacard.framework.*;
import javacard.security.*;

public class TapDanoApplet extends Applet implements TapDanoShareable {

  boolean INITIALIZED = false;
  boolean PAIR_GENERATED = false;
  boolean SIGN_INITIALIZED = false;

  byte[] priKeyEncoded = new byte[32];
  byte[] pubKeyEncoded = new byte[65];
  byte TAG_TYPE;
  boolean TAG_EXTRACT_LOCKED;
  boolean PIN_LOCKED;
  byte[] PIN = new byte[4];

  byte[] lastBuffer = new byte[256];
  byte[] lastResponse = new byte[256];
  byte[] POLICY_ID = new byte[28];
  byte[] TWO_FACTOR_KEY = new byte[32];
  byte[] LAST_SIGNATURE = new byte[72];
  short LAST_SIGNATURE_LENGTH = 72;

  short lastResponseLen;

  byte[] dataToHash = new byte[33];
  byte[] inputPin = new byte[4];

  ECPrivateKey prikey;
  ECPublicKey pubkey;
  KeyPair keypair;
  Signature signature;
  MessageDigest sha256;

  private static final byte[] HEX_CHARS = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  }; 

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
    short offset = 0;
    short outputLength = 0;

    if (!INITIALIZED) initialize();

    if (isNDEF_Write) {
      processTapDano(buffer, offsetIn, (short) 0);
      return 0;
    }

    if (isNDEF_Read) {
      buffer[offset++] = (byte) 0x00;
      buffer[offset++] = (byte) 0x00; // TOTAL LEN
      buffer[offset++] = (byte) 0x81; // HEADER #1: MB=1, ME=0, CF=0, SR=0, IL=0, TNF=0x01 (Well-Known Type)
      buffer[offset++] = (byte) 0x01; // TYPE LENGTH: 1 byte ('U')

      outputLength = (short)(pubKeyEncoded.length * 2);
      short urlLen = (short)(16 + outputLength);
      buffer[offset++] = (byte) 0x00; // PAYLOAD LENGTH
      buffer[offset++] = (byte) 0x00; // PAYLOAD LENGTH
      buffer[offset++] = (byte)(urlLen >> 8);
      buffer[offset++] = (byte)(urlLen & 0x00FF);

      buffer[offset++] = (byte) 0x55; // TYPE: 'U' (URI Record)
      buffer[offset++] = (byte) 0x04; // PAYLOAD - https
      buffer[offset++] = (byte) 0x74; // t
      buffer[offset++] = (byte) 0x61; // a
      buffer[offset++] = (byte) 0x70; // p
      buffer[offset++] = (byte) 0x64; // d
      buffer[offset++] = (byte) 0x61; // a
      buffer[offset++] = (byte) 0x6E; // n
      buffer[offset++] = (byte) 0x6F; // o
      buffer[offset++] = (byte) 0x2E; // .
      buffer[offset++] = (byte) 0x63; // c
      buffer[offset++] = (byte) 0x6F; // o
      buffer[offset++] = (byte) 0x6D; // m
      buffer[offset++] = (byte) 0x2F; // /
      buffer[offset++] = (byte) 0x3F; // ?
      buffer[offset++] = (byte) 0x74; // t
      buffer[offset++] = (byte) 0x3D; // =
      for (short i = 0; i < pubKeyEncoded.length; i++) {
        buffer[offset++] = HEX_CHARS[(pubKeyEncoded[i] >> 4) & 0x0F];
        buffer[offset++] = HEX_CHARS[(pubKeyEncoded[i] & 0x0F)];
      }

      buffer[offset++] = (byte) 0x45; // HEADER #2: MB=0, ME=1, CF=0, SR=0, IL=0, TNF=0x05 (Unknown Type)
      buffer[offset++] = (byte) 0x00; // TYPE LENGTH: 0 byte
      outputLength = processTapDano(buffer, offsetIn, (short)(offset + 4));
      buffer[offset++] = (byte) 0x00; // PAYLOAD LENGTH
      buffer[offset++] = (byte) 0x00; // PAYLOAD LENGTH
      buffer[offset++] = (byte) (outputLength >> 8); // PAYLOAD LENGTH
      buffer[offset++] = (byte) (outputLength & 0x00FF); // PAYLOAD LENGTH
      
      offset += outputLength;

      buffer[0] = (byte)(((short)(offset - 2)) >> 8);
      buffer[1] = (byte)(((short)(offset - 2)) & 0x00FF);
    }

    if (isFIDO) {
      buffer[offset++] = (byte) 0x01;
      buffer[offset++] = (byte) 0x00;
      buffer[offset++] = (byte) 0x00;
      buffer[offset++] = (byte) 0x00;
      buffer[offset++] = (byte) 0x01;
      outputLength = processTapDano(buffer, offsetIn, offset);
      offset += outputLength;
    }
    return offset;
  }

  public short processTapDano(byte[] buffer, byte offsetIn, short offsetOut) {
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
      Util.setShort(buffer, offsetOut, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
      Util.setShort(buffer, (short)(offsetOut + (byte)0x02), JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
      return (short)0x0004;
    }

    short responseLen = getTagInfo(buffer, offsetIn, offsetOut, dataLen);

    return responseLen;
  }

  private void initialize() {
    prikey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    Secp256k1.setCommonCurveParameters(prikey);

    pubkey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    Secp256k1.setCommonCurveParameters(pubkey);

    keypair = new KeyPair(pubkey, prikey);

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    INITIALIZED = true;
    SIGN_INITIALIZED = false;
    PAIR_GENERATED = false;
    Util.arrayFillNonAtomic(priKeyEncoded, (short) 0, (short) priKeyEncoded.length, (byte) 0);
    Util.arrayFillNonAtomic(pubKeyEncoded, (short) 0, (short) pubKeyEncoded.length, (byte) 0);
    Util.arrayFillNonAtomic(POLICY_ID, (short) 0, (short) POLICY_ID.length, (byte) 0);
    Util.arrayFillNonAtomic(TWO_FACTOR_KEY, (short) 0, (short) TWO_FACTOR_KEY.length, (byte) 0);
    Util.arrayFillNonAtomic(LAST_SIGNATURE, (short) 0, (short) LAST_SIGNATURE.length, (byte) 0);
    LAST_SIGNATURE_LENGTH = 72;
  }

  private short getTagInfo(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
    short responseLen = (short) 0;
    buffer[offsetOut++] = (byte) 0x54; // T[ap]
    buffer[offsetOut++] = (byte) 0x44; // D[ano]
    buffer[offsetOut++] = (byte) 0x02; // Version
    buffer[offsetOut++] = (byte) 0x00; // Version
    buffer[offsetOut++] = PAIR_GENERATED ? (byte) 0x01 : (byte) 0x00;
    responseLen = (short) 0x00005;
    if (PAIR_GENERATED) {
      buffer[offsetOut++] = TAG_TYPE;
      buffer[offsetOut++] = TAG_EXTRACT_LOCKED ? (byte) 0x01 : (byte) 0x00;
      buffer[offsetOut++] = PIN_LOCKED ? (byte) 0x01 : (byte) 0x00;
      responseLen += 3;

      boolean showPk = (TAG_TYPE == (byte) 0x02) && (!TAG_EXTRACT_LOCKED) && (!PIN_LOCKED);
      Util.arrayCopyNonAtomic(showPk ? priKeyEncoded : pubKeyEncoded, (short) 0, buffer, offsetOut, (short) (showPk ? priKeyEncoded.length : pubKeyEncoded.length));
      offsetOut += (short) pubKeyEncoded.length;
      responseLen += (short) pubKeyEncoded.length;

      Util.arrayCopyNonAtomic(POLICY_ID, (short) 0, buffer, offsetOut, (short) POLICY_ID.length);
      offsetOut += (short) POLICY_ID.length;
      responseLen += (short) POLICY_ID.length;

      if (!PIN_LOCKED) {
        Util.arrayCopyNonAtomic(TWO_FACTOR_KEY, (short) 0, buffer, offsetOut, (short) TWO_FACTOR_KEY.length);
        offsetOut += (short) 32;
        responseLen += (short) 32;

        Util.arrayCopyNonAtomic(LAST_SIGNATURE, (short) 0, buffer, offsetOut, LAST_SIGNATURE_LENGTH);
        offsetOut += LAST_SIGNATURE_LENGTH;
        responseLen += LAST_SIGNATURE_LENGTH;
      }
    }
    return responseLen;
  }

  private void burnTag(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
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
      prikey = (ECPrivateKey) keypair.getPrivate();
      pubkey = (ECPublicKey) keypair.getPublic();
      prikey.getS(priKeyEncoded, (short) 0);
      pubkey.getW(pubKeyEncoded, (short) 0);
    }

    if (action == (byte) 0x02) { // restore
      prikey.setS(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 2), (short) priKeyEncoded.length);
      pubkey.setW(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 34), (short) pubKeyEncoded.length);
      Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 2), priKeyEncoded, (short) 0, (short) priKeyEncoded.length);
      Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA + 34), pubKeyEncoded, (short) 0, (short) pubKeyEncoded.length);
    }

    // TWO_FACTOR_KEY
    Util.arrayCopyNonAtomic(priKeyEncoded, (short) 0, dataToHash, (short) 0, (short) 32);
    dataToHash[32] = (byte) 0x01;
    sha256.doFinal(dataToHash, (short) 0, (short) dataToHash.length, TWO_FACTOR_KEY, (short) 0);

    PAIR_GENERATED = true;
  }

  public void signData(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) throws CryptoException {
    if (!SIGN_INITIALIZED) {
      signature.init(prikey, Signature.MODE_SIGN);
      SIGN_INITIALIZED = true;
    }
    Util.arrayFillNonAtomic(LAST_SIGNATURE, (short) 0, (short) LAST_SIGNATURE.length, (byte) 0);
    LAST_SIGNATURE_LENGTH = signature.signPreComputedHash(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), dataLen, LAST_SIGNATURE, (short) 0);
  }

  private void formatTag(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
    initialize();
  }

  private void lockTag(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
    TAG_EXTRACT_LOCKED = true;
  }

  private void pinLock(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
    Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), PIN, (short) 0, (short) PIN.length);
    PIN_LOCKED = true;
  }

  private void pinUnlock(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
    Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), inputPin, (short) 0, (short) inputPin.length);
    if (Util.arrayCompare(inputPin, (short) 0, PIN, (short) 0, (short) PIN.length) == 0) {
      PIN_LOCKED = false;
    }
  }

  private void setPolicyId(byte[] buffer, byte offsetIn, short offsetOut, short dataLen) {
    Util.arrayCopyNonAtomic(buffer, (short) (offsetIn + ISO7816.OFFSET_CDATA), POLICY_ID, (short) 0, (short) POLICY_ID.length);
  }
}