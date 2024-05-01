package tapdano;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class TapDanoApplet extends Applet implements TapDanoShareable {

  public final static boolean DEBUG = true;
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

    if (buffer[ISO7816.OFFSET_CLA] != (byte)0x00) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

    try {
      switch (buffer[ISO7816.OFFSET_INS]) {
        case (byte)0xC0:
          try {
            generateKeypair(buffer);
            apdu.setOutgoingAndSend((short)0, (short)64);
          } catch (Exception e) {
            if (Constants.DEBUG) System.out.println("C0 - catch");
            buffer[0] = (byte)0x89;
            apdu.setOutgoingAndSend((short)0, (short) 1);
          }
          break;
          case (byte)0xC1:
          try {
            byte[] msg = new byte[1];
            msg[0] = (byte)0x65;
            byte[] result = signData(msg, (short)0, (short)msg.length);
            Util.arrayCopyNonAtomic(result, (short)0, buffer, (short)0, (short)result.length);
            apdu.setOutgoingAndSend((short) 0, (short)result.length);
          } catch (Exception e) {
            if (Constants.DEBUG) System.out.println("C1 - catch");
            buffer[0] = (byte)0x89;
            apdu.setOutgoingAndSend((short)0, (short) 1);
          }
          break;
        case (byte)0xC2:
          try {
            byte[] result = getLastSign();
            Util.arrayCopyNonAtomic(result, (short)0, buffer, (short)0, (short)result.length);
            apdu.setOutgoingAndSend((short) 0, (short)result.length);
          } catch (Exception e) {
            if (Constants.DEBUG) System.out.println("C2 - catch");
            buffer[0] = (byte)0x89;
            apdu.setOutgoingAndSend((short)0, (short) 1);
          }
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } catch (Exception e) {
      ISOException.throwIt((short)0xff01);
    }
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

  private void generateKeypair(byte[] buffer) {
    if (!INITIALIZED) initialize();
    if (!PAIR_GENERATED) {
      keypair.genKeyPair();

      prikey = (XECKey)keypair.getPrivate();
      pubkey = (XECKey)keypair.getPublic();

      prikey.getEncoded(priKeyEncoded, (short)0);
      pubkey.getEncoded(pubKeyEncoded, (short)0);

      //PAIR_GENERATED = true;
    }

    Util.arrayCopyNonAtomic(priKeyEncoded, (short)0, buffer, (short)0, (short)32);
    Util.arrayCopyNonAtomic(pubKeyEncoded, (short)0, buffer, (short)32, (short)32);
  }

  public byte[] signData(byte[] data, short offset, short length) throws CryptoException {
    if (!SIGN_INITIALIZED) {
      signature.init((Key)prikey, Signature.MODE_SIGN);
      SIGN_INITIALIZED = true;
    }
    signature.sign(data, offset, length, signatureBuffer, (short)0);
    return signatureBuffer;
  }

  public byte[] getLastSign() {
    return signatureBuffer;
  }

  public byte[] exec(byte origin, byte[] buf, short offset, short len) {
    try {
      if (Constants.DEBUG) {
        System.out.println("TapDanoApplet - exec (origin = " + origin + ")");
        StringBuilder sb = new StringBuilder();
        for (short i = 0; i < len; i++) sb.append(String.format("%02X", buf[offset + i]));
        System.out.println("<<" + sb.toString());
      }
  
      if (buf[offset] == (byte)0x77) {
        if (buf[(short)(offset + 1)] == (byte)0x01) {
          byte[] result = new byte[64];
          generateKeypair(result);
          return result;
        }
        if (buf[(short)(offset + 1)] == (byte)0x02) {
          byte[] msg = new byte[1];
          msg[0] = (byte)0x65;
          byte[] result = signData(msg, (short)0, (short)msg.length);
          return result;
        }
        if (buf[(short)(offset + 1)] == (byte)0x03) {
          byte[] result = getLastSign();
          return result;
        }
      }
  
      byte[] result = new byte[1];
      result[0] = (byte) 0x00;
      return result;
    } catch (Exception e) {
      if (Constants.DEBUG) System.out.println("############### Exception ###############");
      byte[] result = new byte[1];
      result[0] = (byte) 0x50;
      return result;
    }
  }
}