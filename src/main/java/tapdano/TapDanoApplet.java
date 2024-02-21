package tapdano;

import javacard.framework.*;
import javacard.security.*;
import tapdano.jcmathlib.*;
import tapdano.swalgs.*;

public class TapDanoApplet extends Applet implements TapDanoShareable {

  public final static boolean DEBUG = true;
  public final static short CARD = OperationSupport.SIMULATOR; // SIMULATOR / JCOP4_P71

  private ResourceManager rm;
  private ECCurve curve;
  private BigNat privateKey, privateNonce, signature;
  private BigNat transformC, transformA3, transformX, transformY, eight;
  private ECPoint point;

  private final byte[] masterKey = new byte[32];
  private final byte[] prefix = new byte[32];
  private final byte[] publicKey = new byte[32];
  private final byte[] publicNonce = new byte[32];

  private MessageDigest hasher;

  private final byte[] ramArray = JCSystem.makeTransientByteArray((short) Wei25519.G.length, JCSystem.CLEAR_ON_DESELECT);
  private final RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

  private boolean initialized = false;

  protected TapDanoApplet(byte[] buf, short offAID, byte lenAID) {
    if (Constants.DEBUG) System.out.println("TapDanoApplet constructor");
    OperationSupport.getInstance().setCard(CARD);
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
    if (initialized) {
      curve.updateAfterReset();
    }
    return true;
  }

  public void process(APDU apdu) {
    if (selectingApplet()) return;

    if (!initialized) initialize();

    byte[] buffer = apdu.getBuffer();

    if (buffer[ISO7816.OFFSET_CLA] != Consts.CLA_ED25519) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

    try {
      switch (buffer[ISO7816.OFFSET_INS]) {
        case Consts.INS_KEYGEN:
          apdu.setOutgoingAndSend((short)0, generateKeypair(buffer));
          break;
        case Consts.INS_SIGN:
          apdu.setOutgoingAndSend((short)0, sign(buffer));
          break;
        case Consts.INS_GET_PRIV:
          if (!DEBUG) ISOException.throwIt(Consts.E_DEBUG_DISABLED);
          privateKey.copyToByteArray(buffer, (short) 0);
          apdu.setOutgoingAndSend((short) 0, (short) 32);
          break;
        case Consts.INS_GET_MASTER:
          if (!DEBUG) ISOException.throwIt(Consts.E_DEBUG_DISABLED);
          Util.arrayCopyNonAtomic(masterKey, (short) 0, buffer, (short) 0, (short) masterKey.length);
          apdu.setOutgoingAndSend((short) 0, (short) masterKey.length);
          break;
        case Consts.INS_GET_PRIV_NONCE:
          if (!DEBUG) ISOException.throwIt(Consts.E_DEBUG_DISABLED);
          privateNonce.copyToByteArray(buffer, (short) 0);
          apdu.setOutgoingAndSend((short) 0, (short) 32);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } catch (ISOException e) {
      throw e; // Our exception from code, just re-emit
    } catch (ArrayIndexOutOfBoundsException e) {
      ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
    } catch (ArithmeticException e) {
      ISOException.throwIt(Consts.SW_ArithmeticException);
    } catch (ArrayStoreException e) {
      ISOException.throwIt(Consts.SW_ArrayStoreException);
    } catch (NullPointerException e) {
      ISOException.throwIt(Consts.SW_NullPointerException);
    } catch (NegativeArraySizeException e) {
      ISOException.throwIt(Consts.SW_NegativeArraySizeException);
    } catch (CryptoException e) {
      ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
    } catch (SystemException e) {
      ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
    } catch (PINException e) {
      ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
    } catch (TransactionException e) {
      ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
    } catch (CardRuntimeException e) {
      ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
    } catch (Exception e) {
      ISOException.throwIt(Consts.SW_Exception);
    }
  }

  private void initialize() {
    if (initialized) ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

    try {
      hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    } catch (CryptoException e) {
      hasher = new Sha2(Sha2.SHA_512);
    }

    rm = new ResourceManager((short) 256);

    privateKey = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);

    privateNonce = new BigNat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
    signature = new BigNat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);

    transformC = new BigNat((short) Consts.TRANSFORM_C.length, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
    transformC.fromByteArray(Consts.TRANSFORM_C, (short) 0, (short) Consts.TRANSFORM_C.length);
    transformA3 = new BigNat((short) Consts.TRANSFORM_A3.length, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
    transformA3.fromByteArray(Consts.TRANSFORM_A3, (short) 0, (short) Consts.TRANSFORM_A3.length);
    transformX = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
    transformY = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

    eight = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
    eight.setValue((byte) 8);

    curve = new ECCurve(Wei25519.p, Wei25519.a, Wei25519.b, Wei25519.G, Wei25519.r, Wei25519.k, rm);
    point = new ECPoint(curve);

    initialized = true;
  }

  private short generateKeypair(byte[] buffer) {
    if (!initialized) ISOException.throwIt(Consts.E_UNINITIALIZED);

    random.generateData(masterKey, (short) 0, (short) 32);

    hasher.reset();
    hasher.doFinal(masterKey, (short) 0, (short) 32, ramArray, (short) 0);

    ramArray[0] &= (byte) 0xf8; // Clear lowest three bits
    ramArray[31] &= (byte) 0x7f; // Clear highest bit
    ramArray[31] |= (byte) 0x40; // Set second-highest bit
    changeEndianity(ramArray, (short) 0, (short) 32);

    Util.arrayCopyNonAtomic(ramArray, (short) 32, prefix, (short) 0, (short) 32);

    privateKey.fromByteArray(ramArray, (short) 0, (short) 32);
    privateKey.shiftRight((short) 3); // Required by smartcards (scalar must be lesser than r)
    point.setW(curve.G, (short) 0, curve.POINT_SIZE);
    point.multiplication(privateKey);
    privateKey.fromByteArray(ramArray, (short) 0, (short) 32); // Reload private key
    privateKey.mod(curve.rBN);

    point.multiplication(eight); // Compensate bit shift

    encodeEd25519(point, publicKey, (short) 0);

    Util.arrayCopyNonAtomic(publicKey, (short) 0, buffer, (short) 0, (short) 32);
    return (short)32;
  }

  private short sign(byte[] buffer) {
    if (!initialized) ISOException.throwIt(Consts.E_UNINITIALIZED);

    short len = (short) ((short) buffer[ISO7816.OFFSET_LC] & (short) 0xff);

    // Generate nonce R
    deterministicNonce(buffer, ISO7816.OFFSET_CDATA, len);

    point.setW(curve.G, (short) 0, curve.POINT_SIZE);
    point.multiplication(privateNonce);
    hasher.reset();
    encodeEd25519(point, ramArray, (short) 0);
    Util.arrayCopyNonAtomic(ramArray, (short) 0, publicNonce, (short) 0, curve.COORD_SIZE);
    hasher.update(ramArray, (short) 0, curve.COORD_SIZE); // R
    hasher.update(publicKey, (short) 0, curve.COORD_SIZE); // A
    
    hasher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0); // m
    changeEndianity(buffer, (short) 0, (short) 64);
    signature.fromByteArray(buffer, (short) 0, (short) 64);
    signature.mod(curve.rBN);
    signature.resize((short) 32);

    // Compute signature s = r + ex
    signature.modMult(privateKey, curve.rBN);
    signature.modAdd(privateNonce, curve.rBN);

    // Return signature (R, s)
    Util.arrayCopyNonAtomic(publicNonce, (short) 0, buffer, (short) 0, curve.COORD_SIZE);
    signature.prependZeros(curve.COORD_SIZE, buffer, curve.COORD_SIZE);
    changeEndianity(buffer, curve.COORD_SIZE, curve.COORD_SIZE);

    return (short)(curve.COORD_SIZE + curve.COORD_SIZE);
  }

  private void encodeEd25519(ECPoint point, byte[] buffer, short offset) {
    point.getW(ramArray, (short) 0);

    // Compute X
    transformX.fromByteArray(ramArray, (short) 1, (short) 32);
    transformY.fromByteArray(ramArray, (short) 33, (short) 32);
    transformX.modSub(transformA3, curve.pBN);
    transformX.modMult(transformC, curve.pBN);
    transformY.modInv(curve.pBN);
    transformX.modMult(transformY, curve.pBN);

    boolean xBit = transformX.isOdd();

    // Compute Y
    transformX.fromByteArray(ramArray, (short) 1, (short) 32);
    transformX.modSub(transformA3, curve.pBN);
    transformY.clone(transformX);
    transformX.decrement();
    transformY.increment();
    transformY.mod(curve.pBN);
    transformY.modInv(curve.pBN);
    transformX.modMult(transformY, curve.pBN);
    transformX.prependZeros(curve.COORD_SIZE, buffer, offset);

    buffer[offset] |= xBit ? (byte) 0x80 : (byte) 0x00;

    changeEndianity(buffer, offset, (short) 32);
  }

  private void changeEndianity(byte[] array, short offset, short len) {
    for (short i = 0; i < (short) (len / 2); ++i) {
      byte tmp = array[(short) (offset + len - i - 1)];
      array[(short) (offset + len - i - 1)] = array[(short) (offset + i)];
      array[(short) (offset + i)] = tmp;
    }
  }

  private void deterministicNonce(byte[] msg, short offset, short len) {
    hasher.reset();
    hasher.update(prefix, (short) 0, (short) 32);
    hasher.doFinal(msg, offset, len, ramArray, (short) 0);
    changeEndianity(ramArray, (short) 0, (short) 64);
    privateNonce.fromByteArray(ramArray, (short) 0, (short) 64);
    privateNonce.mod(curve.rBN);
    privateNonce.resize((short) 32);
  }

  public byte[] exec(byte origin, byte[] buf) {
    if (Constants.DEBUG) System.out.println("TapDanoApplet - exec (origin = " + origin + ")");
    byte[] result = new byte[1];
    result[0] = (byte) 0x01;
    if (origin == (byte) 1) {
      result[0] = (byte) 0x05;
    }
    if (origin == (byte) 2) {
      result[0] = (byte) 0x06;
    }
    return result;
  }
}