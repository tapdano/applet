package tapdano;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public final class NDEFApplet extends Applet {

  /* Instructions */
  private static final byte INS_SELECT = ISO7816.INS_SELECT;
  private static final byte INS_READ_BINARY = (byte) 0xB0;
  private static final byte INS_UPDATE_BINARY = (byte) 0xD6;

  /* File IDs */
  private static final short FILEID_NONE = (short) 0x0000;
  private static final short FILEID_NDEF_CAPABILITIES = (short) 0xE103;
  private static final short FILEID_NDEF_DATA = (short) 0xE104;

  /* File access specifications */
  private static final byte FILE_ACCESS_OPEN = (byte) 0x00;
  private static final byte FILE_ACCESS_NONE = (byte) 0xFF;
  private static final byte FILE_ACCESS_PROP_CONTACT_ONLY = (byte) 0xF0;
  private static final byte FILE_ACCESS_PROP_WRITE_ONCE = (byte) 0xF1;

  /* Parameters for SELECT */
  private static final byte SELECT_P1_BY_FILEID = (byte) 0x00;
  private static final byte SELECT_P2_FIRST_OR_ONLY = (byte) 0x0C;

  /* NDEF mapping version (specification 2.0) */
  private static final byte NDEF_MAPPING_VERSION = (byte) 0x20;

  /* Install parameter tags */
  private static final byte AD_TAG_NDEF_DATA_INITIAL = (byte) 0x80;
  private static final byte AD_TAG_NDEF_DATA_ACCESS = (byte) 0x81;
  private static final byte AD_TAG_NDEF_DATA_SIZE = (byte) 0x82;

  /* Constants related to capability container */
  private static final byte CC_LEN_HEADER = 7;
  private static final byte CC_OFF_NDEF_FILE_CONTROL = 0x07;
  private static final byte CC_TAG_NDEF_FILE_CONTROL = 0x04;
  private static final byte CC_LEN_NDEF_FILE_CONTROL = 6;

  /* Constants related to file control data in capabilities */
  private static final byte FC_OFF_FILE_ID = 0x00;
  private static final byte FC_OFF_SIZE = 0x02;
  private static final byte FC_OFF_READ_ACCESS = 0x04;
  private static final byte FC_OFF_WRITE_ACCESS = 0x05;

  /**
   * Configuration: support for writing
   *
   * If disabled then no writing will be allowed after
   * initialization. Intended for use in combination
   * with install parameters.
   */
  private static final boolean FEATURE_WRITING = true;

  /**
   * Configuration: support advanced access restrictions
   *
   * If enabled the applet will support the special
   * access modes "contact only" as well as "write once".
   *
   * Disabling this saves about 170 bytes.
   */
  private static final boolean FEATURE_ADVANCED_ACCESS_CONTROL = true;

  /**
   * Configuration: maximum read block size
   */
  private static final short NDEF_MAX_READ = 128;

  /**
   * Configuration: maximum write block size
   */
  private static final short NDEF_MAX_WRITE = 128;

  /**
   * Configuration: maximum size of data file
   *
   * Two bytes are used for the record length,
   * the rest will be available for an NDEF record.
   */
  private static final short DEFAULT_NDEF_DATA_SIZE = 256;

  /**
   * Configuration: default read access for data file
   */
  private static final byte DEFAULT_NDEF_READ_ACCESS = FILE_ACCESS_OPEN;

  /**
   * Configuration: default write access for data file
   */
  private static final byte DEFAULT_NDEF_WRITE_ACCESS = FILE_ACCESS_OPEN;

  /** Transient variables */
  private short[] vars;
  /** Variable index for currently selected file */
  private static final byte VAR_SELECTED_FILE = (byte) 0;
  /** Number of transient variables */
  private static final short NUM_VARS = (short) 1;

  /** NDEF capability file contents */
  private final byte[] capsFile;
  /** NDEF data file contents */
  private final byte[] dataFile;

  /** NDEF data read access policy */
  private final byte dataReadAccess;
  /** NDEF data write access policy */
  private final byte dataWriteAccess;

  /**
   * Installs an NDEF applet
   *
   * Will create, initialize and register an instance of
   * this applet as specified by the provided install data.
   *
   * Requested AID will always be honored.
   * Control information is ignored.
   * Applet data will be used for initialization.
   *
   * @param buf containing install data
   * @param off offset of install data in buf
   * @param len length of install data in buf
   */
  public static void install(byte[] buf, short off, byte len) {
    if (Constants.DEBUG) System.out.println("NDEFApplet install");
    short pos = off;
    // find AID
    byte lenAID = buf[pos++];
    short offAID = pos;
    new NDEFApplet().register(buf, offAID, lenAID);
  }

  protected NDEFApplet() {
    if (Constants.DEBUG) System.out.println("NDEFApplet constructor");
    
    short initSize = DEFAULT_NDEF_DATA_SIZE;
    byte initReadAccess = DEFAULT_NDEF_READ_ACCESS;
    byte initWriteAccess = DEFAULT_NDEF_WRITE_ACCESS;
    byte[] initBuf = null;
    short initOff = 0;
    short initLen = 0;

    // create variables
    vars = JCSystem.makeTransientShortArray(NUM_VARS, JCSystem.CLEAR_ON_DESELECT);

    // squash write access if not supported
    if (!FEATURE_WRITING) {
      initWriteAccess = FILE_ACCESS_NONE;
    }

    // set up access
    dataReadAccess = initReadAccess;
    dataWriteAccess = initWriteAccess;

    // create file contents
    capsFile = makeCaps(initSize, initReadAccess, initWriteAccess);
    dataFile = makeData(initSize, initBuf, initOff, initLen);
  }

  /**
   * Create and initialize the CAPABILITIES file
   *
   * @param dataSize        to be allocated
   * @param dataReadAccess  to put in the CC
   * @param dataWriteAccess to put in the CC
   * @return an array for use as the CC file
   */
  private byte[] makeCaps(short dataSize, byte dataReadAccess, byte dataWriteAccess) {
    short capsLen = (short) (CC_LEN_HEADER + 2 + CC_LEN_NDEF_FILE_CONTROL);
    byte[] caps = new byte[capsLen];

    short pos = 0;

    // CC length
    pos = Util.setShort(caps, pos, capsLen);
    // mapping version
    caps[pos++] = NDEF_MAPPING_VERSION;
    // maximum read size
    pos = Util.setShort(caps, pos, NDEF_MAX_READ);
    // maximum write size
    pos = Util.setShort(caps, pos, NDEF_MAX_WRITE);

    // NDEF File Control TLV
    caps[pos++] = CC_TAG_NDEF_FILE_CONTROL;
    caps[pos++] = CC_LEN_NDEF_FILE_CONTROL;
    // file ID
    pos = Util.setShort(caps, pos, FILEID_NDEF_DATA);
    // file size
    pos = Util.setShort(caps, pos, dataSize);
    // read access
    caps[pos++] = dataReadAccess;
    // write access
    caps[pos++] = dataWriteAccess;

    // check consistency
    if (pos != capsLen) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    // return the file
    return caps;
  }

  /**
   * Create and initialize the DATA file
   *
   * @param dataSize to be allocated
   * @param init     buffer containing initial data
   * @param initOff  offset of initial data in buffer
   * @param initLen  length of initial data in buffer
   * @return an array for use as the data file
   */
  private byte[] makeData(short dataSize, byte[] init, short initOff, short initLen) {
    byte[] data = new byte[dataSize];
    return data;
  }

  /**
   * Fix up a capability container
   *
   * This will be called to fix up capabilities before
   * they are actually sent out to the host device.
   *
   * Currently this only fixes up the access policies
   * so as to hide our proprietary policies.
   *
   * @param caps buffer containing CC to fix
   * @param off  offset of CC in buffer
   * @param len  of CC in buffer
   */
  private void fixCaps(byte[] caps, short off, short len) {
    if (FEATURE_ADVANCED_ACCESS_CONTROL) {
      short offNFC = (short) (off + CC_OFF_NDEF_FILE_CONTROL + 2);
      short offR = (short) (offNFC + FC_OFF_READ_ACCESS);
      short offW = (short) (offNFC + FC_OFF_WRITE_ACCESS);
      caps[offR] = fixAccess(dataFile, dataReadAccess);
      caps[offW] = fixAccess(dataFile, dataWriteAccess);
    }
  }

  /**
   * Process an APDU
   *
   * This is the outer layer of our APDU dispatch.
   *
   * It deals with the CLA and INS of the APDU,
   * leaving the rest to an INS-specific function.
   *
   * @param apdu to be processed
   * @throws ISOException on error
   */
  public final void process(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();
    byte ins = buffer[ISO7816.OFFSET_INS];

    // handle selection of the applet
    if (selectingApplet()) {
      vars[VAR_SELECTED_FILE] = FILEID_NONE;
      return;
    }

    // secure messaging is not supported
    if (apdu.isSecureMessagingCLA()) {
      ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
    }

    // process commands to the applet
    if (apdu.isISOInterindustryCLA()) {
      if (ins == INS_SELECT) {
        processSelect(apdu);
      } else if (ins == (byte)0x78) {
        if (Constants.DEBUG) System.out.println("### 0x78");
      } else if (ins == (byte)0x88) {
        if (Constants.DEBUG) System.out.println("### 0x88");
        AID TapDanoAID = new AID(Constants.TapDanoAIDBytes, (short)0, (byte)Constants.TapDanoAIDBytes.length);
        TapDanoShareable tapDano = (TapDanoShareable)JCSystem.getAppletShareableInterfaceObject(TapDanoAID, (byte)0x00);
        if (tapDano != null) {
          byte[] result = tapDano.exec((byte)0x01, buffer, (short)0, (short)0);
          apdu.setOutgoing();
          apdu.setOutgoingLength((short)result.length);
          apdu.sendBytesLong(result, (short)0, (short)result.length);
        }
      } else if (ins == INS_READ_BINARY) {
        processReadBinary(apdu);
      } else if (ins == INS_UPDATE_BINARY) {
        if (FEATURE_WRITING) {
          processUpdateBinary(apdu);
        } else {
          ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
      } else {
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } else {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }

  /**
   * Process a SELECT command
   *
   * This handles only the one case mandated by the NDEF
   * specification: SELECT FIRST-OR-ONLY BY-FILE-ID.
   *
   * The file ID is specified in the APDU contents. It
   * must be exactly two bytes long and also valid.
   *
   * @param apdu to process
   * @throws ISOException on error
   */
  private void processSelect(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];

    // we only support what the NDEF spec prescribes
    if (p1 != SELECT_P1_BY_FILEID || p2 != SELECT_P2_FIRST_OR_ONLY) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // receive data
    short lc = apdu.setIncomingAndReceive();

    // check length, must be for a file ID
    if (lc != 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // retrieve the file ID
    short fileId = Util.getShort(buffer, ISO7816.OFFSET_CDATA);

    // perform selection if the ID is valid
    if (fileId == FILEID_NDEF_CAPABILITIES || fileId == FILEID_NDEF_DATA) {
      vars[VAR_SELECTED_FILE] = fileId;
    } else {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }
  }

  /**
   * Process a READ BINARY command
   *
   * This supports simple reads at any offset.
   *
   * The length of the returned data is limited
   * by the maximum R-APDU length as well as by
   * the maximum read size NDEF_MAX_READ.
   *
   * @param apdu to process
   * @throws ISOException on error
   */
  private void processReadBinary(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();

    // access the file
    byte[] file = accessFileForRead(vars[VAR_SELECTED_FILE]);

    // get and check the read offset
    short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
    if (offset < 0 || offset >= file.length) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }

    // determine the output size
    short le = apdu.setOutgoingNoChaining();
    if (le > NDEF_MAX_READ) {
      le = NDEF_MAX_READ;
    }

    // adjust for end of file
    short limit = (short) (offset + le);
    if (limit < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (limit >= file.length) {
      le = (short) (file.length - offset);
    }

    // send the requested data
    if (vars[VAR_SELECTED_FILE] == FILEID_NDEF_CAPABILITIES) {
      // send fixed capabilities
      Util.arrayCopyNonAtomic(file, (short) 0,
          buffer, (short) 0,
          (short) file.length);
      fixCaps(buffer, (short) 0, (short) file.length);
      apdu.setOutgoingLength(le);
      apdu.sendBytesLong(buffer, offset, le);
    } else {
      // send directly
      apdu.setOutgoingLength(le);
      apdu.sendBytesLong(file, offset, le);
    }
  }

  /**
   * Process an UPDATE BINARY command
   *
   * Supports simple writes at any offset.
   *
   * The amount of data that can be written in one
   * operation is limited both by maximum C-APDU
   * length and the maximum write size NDEF_MAX_WRITE.
   *
   * @param apdu to process
   * @throws ISOException on error
   */
  private void processUpdateBinary(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();

    // access the file
    byte[] file = accessFileForWrite(vars[VAR_SELECTED_FILE]);

    // get and check the write offset
    short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
    if (offset < 0 || offset >= file.length) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }

    // receive data
    short lc = apdu.setIncomingAndReceive();

    // check the input size
    if (lc > NDEF_MAX_WRITE) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // file limit checks
    short limit = (short) (offset + lc);
    if (limit < 0 || limit >= file.length) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // perform the update
    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, file, offset, lc);
  }

  /**
   * Check if file access should be granted
   *
   * This will perform all necessary checks to determine
   * if an operation can currently be allowed within the
   * policy specified in ACCESS.
   *
   * @param access policy to be checked
   * @return true if access granted, false otherwise
   */
  private boolean checkAccess(byte[] data, byte access) {
    if (!FEATURE_ADVANCED_ACCESS_CONTROL) {
      // simple access control
      return access == FILE_ACCESS_OPEN;
    } else {
      // get protocol and media information
      byte protocol = APDU.getProtocol();
      byte media = (byte) (protocol & APDU.PROTOCOL_MEDIA_MASK);
      // make the decision
      switch (access) {
        case FILE_ACCESS_OPEN:
          return true;
        case FILE_ACCESS_PROP_CONTACT_ONLY:
          return media == APDU.PROTOCOL_MEDIA_DEFAULT;
        case FILE_ACCESS_PROP_WRITE_ONCE:
          return data[0] == 0 && data[1] == 0;
        default:
        case FILE_ACCESS_NONE:
          return false;
      }
    }
  }

  /**
   * Fix up an access policy to reflect current state
   *
   * This is used to squash our custom access policies
   * so that we do not have to present a proprietary
   * policy to unsuspecting host devices.
   *
   * @param data   of the file for which to fix
   * @param access policy for to fix
   * @return a fixed access policy
   */
  private byte fixAccess(byte[] data, byte access) {
    // figure out the right policy
    switch (access) {
      // by default we pass through
      default:
        return access;
      // these two require fixing
      case FILE_ACCESS_PROP_CONTACT_ONLY:
      case FILE_ACCESS_PROP_WRITE_ONCE:
        return (checkAccess(data, access))
            ? FILE_ACCESS_OPEN
            : FILE_ACCESS_NONE;
    }
  }

  /**
   * Access a file for reading
   *
   * This function serves to perform precondition checks
   * before actually operating on a file in a read operation.
   *
   * If this function succeeds then the given fileId was
   * valid, security access has been granted and reading
   * of data for this file is possible.
   *
   * @param fileId of the file to be read
   * @return data array of the file
   * @throws ISOException on error
   */
  private byte[] accessFileForRead(short fileId) throws ISOException {
    byte[] file = null;
    byte access = FILE_ACCESS_NONE;
    // select relevant data
    if (fileId == FILEID_NDEF_CAPABILITIES) {
      file = capsFile;
      access = FILE_ACCESS_OPEN;
    }
    if (fileId == FILEID_NDEF_DATA) {
      file = dataFile;
      access = dataReadAccess;
    }
    // check that we got anything
    if (file == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // perform access checks
    if (!checkAccess(file, access)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    return file;
  }

  /**
   * Access a file for writing
   *
   * This function serves to perform precondition checks
   * before actually operating on a file in a write operation.
   *
   * If this function succeeds then the given fileId was
   * valid, security access has been granted and writing
   * of data for this file is possible.
   *
   * @param fileId of the file to be written
   * @return data array of the file
   * @throws ISOException on error
   */
  private byte[] accessFileForWrite(short fileId) throws ISOException {
    byte[] file = null;
    byte access = FILE_ACCESS_NONE;
    // CC can not be written
    if (fileId == FILEID_NDEF_CAPABILITIES) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
    // select relevant data
    if (fileId == FILEID_NDEF_DATA) {
      file = dataFile;
      access = dataWriteAccess;
    }
    // check that we got something
    if (file == null) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // perform access checks
    if (!checkAccess(file, access)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    return file;
  }

}