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

  NamedParameterSpec params;
  XECKey prikey;
  XECKey pubkey;
  KeyPair keypair;
  Signature signature;
  byte[] signatureBuffer = new byte[64];

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

    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA0) {
      buffer[offsetOut++] = (byte)0xAB;
      buffer[offsetOut++] = (byte)0xCD;
      return (short)2;
    }

    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA1) {
      return generateKeypair(buffer, offsetIn, offsetOut);
    }

    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA2) {
      return signData(buffer, offsetIn, offsetOut);
    }

    /*
    if (buffer[(byte)(offsetIn + ISO7816.OFFSET_INS)] == (byte)0xA3) {
      byte[] result = getLastSign();
      return result;
    }
    */

    buffer[offsetOut++] = (byte)0x6D;
    buffer[offsetOut++] = (byte)0x00;
    return (short)2;
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

  public short signData(byte[] buffer, byte offsetIn, byte offsetOut) throws CryptoException {
    if (!SIGN_INITIALIZED) {
      signature.init((Key)prikey, Signature.MODE_SIGN);
      SIGN_INITIALIZED = true;
    }
    short msgLen = (short)buffer[(byte)(offsetIn + ISO7816.OFFSET_LC)];
    signature.sign(buffer, (short)(offsetIn + ISO7816.OFFSET_CDATA), msgLen, signatureBuffer, (short)0);
    Util.arrayCopyNonAtomic(signatureBuffer, (short)0, buffer, (short)offsetOut, (short)signatureBuffer.length);
    return (short)signatureBuffer.length;
  }

  public byte[] getLastSign() {
    return signatureBuffer;
  }
}