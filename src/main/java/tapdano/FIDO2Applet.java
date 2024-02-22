package tapdano;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
public final class FIDO2Applet extends Applet implements ExtendedLength {
    private static final byte FIRMWARE_VERSION = 0x04;
    private boolean LOW_SECURITY_MAXIMUM_COMPLIANCE;
    private boolean FORCE_ALWAYS_UV;
    private short MAX_RAM_SCRATCH_SIZE;
    private short BUFFER_MEM_SIZE;
    private short FLASH_SCRATCH_SIZE;
    private static final short IV_LEN = 16;
    private byte MAX_CRED_BLOB_LEN;
    private static final byte MAX_RP_IDS_MIN_PIN_LENGTH = 2;
    private static final short KEY_POINT_LENGTH = 32;
    private static final short RP_HASH_LEN = 32;
    private static final short CREDENTIAL_PAYLOAD_LEN = (short)(RP_HASH_LEN + KEY_POINT_LENGTH + 16);
    private static final short CREDENTIAL_ID_LEN = (short)(CREDENTIAL_PAYLOAD_LEN + IV_LEN + 16);
    private static final short CLIENT_DATA_HASH_LEN = 32;
    private static final short APPROXIMATE_STORAGE_PER_RESIDENT_KEY = 400;
    private byte[] bufferMem;
    private boolean pinSet;
    private byte minPinLength = 4;
    private boolean forcePinChange = false;
    private KeyPair authenticatorKeyAgreementKey;
    private final byte[] hmacWrapperBytesUV;
    private final byte[] hmacWrapperBytesNoUV;
    private final byte[] credentialVerificationKey;
    private byte[] permissionsRpId;
    private final byte[] pinKDFSalt;
    private final byte[] wrappingKeySpace;
    private final AESKey highSecurityWrappingKey;
    private final AESKey lowSecurityWrappingKey;
    private final byte[] highSecurityWrappingIV;
    private final byte[] wrappingKeyValidation;
    private final RandomData random;
    private final SigOpCounter counter;
    private KeyPair ecKeyPair;
    private byte[] attestationData;
    private short filledAttestationData;
    private final MessageDigest sha256;
    private boolean alwaysUv;
    private final TransientStorage transientStorage;
    private BufferManager bufferManager;
    private final byte[] largeBlobStoreA;
    private final byte[] largeBlobStoreB;
    private byte largeBlobStoreIndex = 0;
    private final byte[] aaguid = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    private static void sendByteArray(APDU apdu, byte[] array, short len) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(array, (short) 0, buffer, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    private void sendNoCopy(APDU apdu, short len) {
        bufferManager.clear();
        apdu.setOutgoingAndSend((short) 0, len);
    }
    private byte[] fullyReadReq(APDU apdu, short lc, short amtRead, boolean forceBuffering) {
        byte[] buffer = apdu.getBuffer();
        transientStorage.clearAssertIterationPointer();
        final short chainOff = transientStorage.getChainIncomingReadOffset();
        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), bufferMem, chainOff, amtRead);
        short curRead = amtRead;
        while (curRead < lc) {
            short read = apdu.receiveBytes((short) 0);
            Util.arrayCopyNonAtomic(buffer, (short) 0, bufferMem, (short) (curRead + chainOff), read);
            curRead = (short) (curRead + read);
        }
        bufferManager.informAPDUBufferAvailability(apdu, (short) 0xFF);
        if (!apdu.isCommandChainingCLA()) {
            transientStorage.resetChainIncomingReadOffset();
        }
        return bufferMem;
    }
    private void loadWrappingKeyIfNoPIN() {
        if (!pinSet) {
            highSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
        }
    }
    private void hmacSha256(APDU apdu, byte[] keyBuff, short keyOff,
                            byte[] content, short contentOff, short contentLen,
                            byte[] outputBuff, short outputOff) {
        final short scratchAmt = (short) ((contentLen < 32 ? 32 : contentLen) + 64);
        short scratchHandle = bufferManager.allocate(apdu, scratchAmt, BufferManager.ANYWHERE);
        byte[] workingBuffer = bufferManager.getBufferForHandle(apdu, scratchHandle);
        short workingFirst = bufferManager.getOffsetForHandle(scratchHandle);
        short workingSecond = (short)(workingFirst + 32);
        short workingMessage = (short)(workingSecond + 32);
        for (short i = 0; i < 32; i++) {
            workingBuffer[(short) (workingFirst + i)] = (byte) (keyBuff[(short)(i + keyOff)] ^ (0x36)); 
        }
        Util.arrayFillNonAtomic(workingBuffer, workingSecond, (short) 32, (byte) 0x36);
        Util.arrayCopyNonAtomic(content, contentOff,
                workingBuffer, workingMessage, contentLen);
        sha256.doFinal(workingBuffer, workingFirst, (short)(64 + contentLen),
                workingBuffer, workingMessage);
        for (short i = 0; i < 32; i++) {
            workingBuffer[(short) (workingFirst + i)] = (byte) (keyBuff[(short)(i + keyOff)] ^ (0x5c)); 
        }
        Util.arrayFillNonAtomic(workingBuffer, workingSecond, (short) 32, (byte) 0x5c);
        sha256.doFinal(workingBuffer, workingFirst, (short) 96, outputBuff, outputOff);
        bufferManager.release(apdu, scratchHandle, scratchAmt);
    }
    private short writeADBasic(byte[] outBuf, short adLen, short writeIdx, byte flags, byte[] rpIdBuffer, short rpIdOffset) {
        short ow = writeIdx;
        writeIdx = encodeIntLenTo(outBuf, writeIdx, adLen, true);
        short adAddlBytes = (short)(writeIdx - ow);
        writeIdx = Util.arrayCopyNonAtomic(rpIdBuffer, rpIdOffset, outBuf, writeIdx, RP_HASH_LEN);
        outBuf[writeIdx++] = flags; 
        encodeCounter(outBuf, writeIdx);
        return adAddlBytes;
    }
    private void encodeCounter(byte[] buf, short off) {
        random.generateData(buf, off, (short) 1);
        counter.increment((short)((buf[off] & 0x0E) + 1));
        counter.pack(buf, off);
    }
    private void getAssertion(final APDU apdu, final short lc, final byte[] buffer) {
        short readIdx = 1;
        final byte startingAllowedMemory = BufferManager.NOT_APDU_BUFFER;
        short scratchRPIDHashHandle = bufferManager.allocate(apdu, RP_HASH_LEN, startingAllowedMemory);
        byte[] scratchRPIDHashBuffer = bufferManager.getBufferForHandle(apdu, scratchRPIDHashHandle);
        short scratchRPIDHashIdx = bufferManager.getOffsetForHandle(scratchRPIDHashHandle);
        short clientDataHashHandle = bufferManager.allocate(apdu, CLIENT_DATA_HASH_LEN, startingAllowedMemory);
        byte[] clientDataHashBuffer = bufferManager.getBufferForHandle(apdu, clientDataHashHandle);
        short clientDataHashIdx = bufferManager.getOffsetForHandle(clientDataHashHandle);
        short stateKeepingHandle = bufferManager.allocate(apdu, (short) 2, startingAllowedMemory);
        byte[] stateKeepingBuffer = bufferManager.getBufferForHandle(apdu, stateKeepingHandle);
        short stateKeepingIdx = bufferManager.getOffsetForHandle(stateKeepingHandle);
        short hmacSaltHandle = bufferManager.allocate(apdu, (short) 65, startingAllowedMemory);
        byte[] hmacSaltBuffer = bufferManager.getBufferForHandle(apdu, hmacSaltHandle);
        short hmacSaltIdx = bufferManager.getOffsetForHandle(hmacSaltHandle);
        final short credStorageHandle = bufferManager.allocate(apdu, CREDENTIAL_ID_LEN, startingAllowedMemory);
        final short credStorageOffset = bufferManager.getOffsetForHandle(credStorageHandle);
        final byte[] credStorageBuffer = bufferManager.getBufferForHandle(apdu, credStorageHandle);
        stateKeepingBuffer[stateKeepingIdx] = 1; 
        stateKeepingBuffer[(short)(stateKeepingIdx + 1)] = 0;
        final short numParams = (short)(ub(buffer[readIdx++]) - 0x00A0);

        readIdx++;
        short rpIdLen;
        if (buffer[readIdx] == 0x78) { 
            readIdx++;
            rpIdLen = buffer[readIdx++];
        } else if (buffer[readIdx] >= 0x61 && buffer[readIdx] < 0x78) { 
            rpIdLen = (short) (buffer[readIdx] - 0x60);
            readIdx++;
        } else {
            return; 
        }

        final short rpIdIdx = readIdx;
        readIdx += rpIdLen;
        readIdx++;
        if (buffer[readIdx++] == 0x58) readIdx++;
        Util.arrayCopyNonAtomic(buffer, readIdx, clientDataHashBuffer, clientDataHashIdx, CLIENT_DATA_HASH_LEN);
        readIdx += CLIENT_DATA_HASH_LEN;

        sha256.doFinal(buffer, rpIdIdx, rpIdLen, scratchRPIDHashBuffer, scratchRPIDHashIdx);

        short allowListIdx = -1;
        short paramsRead = 2;
        readIdx++;
        allowListIdx = readIdx;
        paramsRead++;

        readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
        transientStorage.defaultOptions();

        for (short i = paramsRead; i < numParams; i++) {
            byte mapKey = buffer[readIdx++];
            if (mapKey == 0x05) {
                readIdx = processOptionsMap(apdu, buffer, readIdx, lc, false, false);
            } else {
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
        }
        loadWrappingKeyIfNoPIN();
        short blockReadIdx = allowListIdx;
        blockReadIdx++;
        blockReadIdx = consumeMapAndGetID(apdu, buffer, blockReadIdx, lc, true, true, false, false);
        final short credIdx = transientStorage.getStoredIdx();
        final short credLen = transientStorage.getStoredLen();
        Util.arrayCopyNonAtomic(buffer, credIdx, credStorageBuffer, credStorageOffset, credLen);
        hmacSaltBuffer[hmacSaltIdx] = 0;
        byte potentialAssertionIterationPointer = 0;
        
        byte[] outputBuffer = bufferMem;
        short outputIdx = (short) 0;
        outputBuffer[outputIdx++] = FIDOConstants.CTAP2_OK;
        byte numMapEntries = 4;
        outputBuffer[outputIdx++] = (byte) (0xA0 + numMapEntries); 

        outputBuffer[outputIdx++] = 0x01; 
        outputIdx = packCredentialId(credStorageBuffer, credStorageOffset, outputBuffer, outputIdx);

        outputBuffer[outputIdx++] = 0x02;
        byte flags = transientStorage.hasUPOption() ? (byte) 0x01 : 0x00;
        short adLen = (short)37;
        final short adAddlBytes = writeADBasic(outputBuffer, adLen, outputIdx, flags, scratchRPIDHashBuffer, scratchRPIDHashIdx);
        final short startOfAD = (short) (outputIdx + adAddlBytes);
        outputIdx = (short) (startOfAD + adLen);
        Util.arrayCopyNonAtomic(clientDataHashBuffer, clientDataHashIdx, outputBuffer, outputIdx, CLIENT_DATA_HASH_LEN);

        outputBuffer[outputIdx++] = 0x03;
        if (transientStorage.hasUPOption()) {
            AID TapDanoAID = new AID(Constants.TapDanoAIDBytes, (short)0, (byte)Constants.TapDanoAIDBytes.length);
            TapDanoShareable tapDano = (TapDanoShareable)JCSystem.getAppletShareableInterfaceObject(TapDanoAID, (byte)0x00);
            if (tapDano != null) {
              byte[] result = tapDano.exec((byte)0x02, credStorageBuffer, credStorageOffset, credLen);
              outputIdx = encodeIntLenTo(outputBuffer, outputIdx, (short)result.length, true);
              Util.arrayCopyNonAtomic(result, (short)0, outputBuffer, outputIdx, (short)result.length);
              outputIdx += (short)result.length;
            }
        } else {
            short fakeSignatureLength = 32;
            outputIdx = encodeIntLenTo(outputBuffer, outputIdx, fakeSignatureLength, true);
            for (short i = 0; i < fakeSignatureLength; i++) outputBuffer[outputIdx++] = (byte)0x00;
        }

        outputBuffer[outputIdx++] = 0x04; 
        short uidLen = 1;
        outputIdx = Util.arrayCopyNonAtomic(CannedCBOR.SINGLE_ID_MAP_PREAMBLE, (short) 0, outputBuffer, outputIdx, (short) CannedCBOR.SINGLE_ID_MAP_PREAMBLE.length);
        outputIdx = encodeIntLenTo(outputBuffer, outputIdx, uidLen, true);
        outputBuffer[outputIdx] = (byte)49;
        outputIdx += uidLen; 
        ecKeyPair.getPrivate().clearKey();
        transientStorage.setAssertIterationPointer(potentialAssertionIterationPointer);
        doSendResponse(apdu, outputIdx);
    }
    private short getMapEntryCount(APDU apdu, byte cborMapDeclaration) {
        short sb = ub(cborMapDeclaration);
        return (short)(sb - 0x00A0);
    }
    private short processOptionsMap(APDU apdu, byte[] buffer, short readIdx, short lc, boolean requireUP, boolean allowRK) {
        short numOptions = getMapEntryCount(apdu, buffer[readIdx++]);
        for (short j = 0; j < numOptions; j++) {
            short optionStrLen = (short)(buffer[readIdx++] & 0x0F);
            if (optionStrLen != 2 || (buffer[readIdx] != 'u' && buffer[readIdx] != 'r')) {
                readIdx += optionStrLen;
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                continue;
            }
            if (buffer[readIdx] == 'r' && buffer[(short)(readIdx+1)] == 'k') {
                // rk option
                readIdx += 2;
                if (buffer[readIdx] == (byte) 0xF5) { // true
                    transientStorage.setRKOption(true);
                } else if (buffer[readIdx] == (byte) 0xF4) { // false
                    transientStorage.setRKOption(false);
                }
            } else {
                short pOrVPos = ++readIdx;
                if (buffer[pOrVPos] != 'p' && buffer[pOrVPos] != 'v') {
                    // unknown two-character option starting with 'u'...
                    readIdx++;
                    readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                    continue;
                }
                byte val = buffer[++readIdx];
                if (val == (byte) 0xF5) { // true
                    if (buffer[pOrVPos] == 'p') {
                        transientStorage.setUPOption(true);
                    } else {
                        transientStorage.setUVOption(true);
                    }
                } else if (val == (byte) 0xF4) { // false
                    if (buffer[pOrVPos] == 'p') {
                        transientStorage.setUPOption(false);
                    } else {
                        transientStorage.setUVOption(false);
                    }
                }
            }
            readIdx++;
        }
        if (requireUP) {
            // UP defaults to true in this case
            transientStorage.setUPOption(true);
        }
        return readIdx;
    }
    private short encodeIntLenTo(byte[] outBuf, short writeIdx, short v, boolean byteString) {
        if (v < 24) {
            outBuf[writeIdx++] = (byte)((byteString ? 0x40 : 0x60) + v); 
        } else if (v < 256) {
            outBuf[writeIdx++] = (byte)(byteString ? 0x58 : 0x78); 
            outBuf[writeIdx++] = (byte) v;
        } else {
            outBuf[writeIdx++] = (byte)(byteString ? 0x59 : 0x79); 
            writeIdx = Util.setShort(outBuf, writeIdx, v);
        }
        return writeIdx;
    }
    private void setupChainedResponse(short offset, short remaining) {
        transientStorage.setOutgoingContinuation(offset, remaining);
        if (remaining >= 256) {
            throwException(ISO7816.SW_BYTES_REMAINING_00, false);
        } else {
            throwException((short) (ISO7816.SW_BYTES_REMAINING_00 + remaining), false);
        }
    }
    private void doSendResponse(APDU apdu, short outputLen) {
        bufferManager.clear();
        final boolean lbk = transientStorage.shouldStreamLBKLater();
        final short apduBlockSize = (short)(APDU.getOutBlockSize() - 2);
        final short expectedLen = apdu.setOutgoing();
        short totalOutputLen = outputLen;
        if (lbk) totalOutputLen = (short)(totalOutputLen + 35); 
        short amountFitInBuffer = totalOutputLen;
        if (amountFitInBuffer > expectedLen) amountFitInBuffer = expectedLen;
        if (amountFitInBuffer > apduBlockSize) amountFitInBuffer = apduBlockSize;
        short amountFromMem = amountFitInBuffer;
        if (amountFromMem > outputLen) amountFromMem = outputLen;
        apdu.setOutgoingLength(amountFitInBuffer);
        final byte[] apduBytes = apdu.getBuffer();
        Util.arrayCopyNonAtomic(bufferMem, (short) 0, apduBytes, (short) 0, amountFromMem);
        apdu.sendBytes((short) 0, amountFitInBuffer);
        if (totalOutputLen > amountFitInBuffer) {
            setupChainedResponse(amountFitInBuffer, (short)(totalOutputLen - amountFitInBuffer));
        }
    }
    private static short ub(byte b) {
        return (short)(0xFF & b);
    }
    private short consumeAnyEntity(APDU apdu, byte[] buffer, short readIdx, short lc) {
        byte b = buffer[readIdx];
        short s = ub(b);
        if ((s >= 0x0000 && s <= 0x0017) || (s >= 0x0020 && s <= 0x0037) || s == 0x00F4 || s == 0x00F5 || s == 0x00F6) {
            return (short)(readIdx + 1);
        }
        if (s == 0x0018 || s == 0x0038) {
            return (short) (readIdx + 2);
        }
        if (s == 0x0019 || s == 0x0039) {
            return (short) (readIdx + 3);
        }
        if (s == 0x0058 || s == 0x0078) {
            return (short) (readIdx + 2 + ub(buffer[(short)(readIdx+1)]));
        }
        if (s == 0x0059 || s == 0x0079) {
            short len = Util.getShort(buffer, (short)(readIdx + 1));
            return (short) (readIdx + 3 + len);
        }
        if (s >= 0x0040 && s <= 0x0057) {
            return (short)(readIdx + 1 + s - 0x0040);
        }
        if (s >= 0x0060 && s <= 0x0077) {
            return (short)(readIdx + 1 + s - 0x0060);
        }
        if (s == 0x0098) {
            short l = ub(buffer[++readIdx]);
            readIdx++;
            for (short i = 0; i < l; i++) {
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s == 0x0099) {
            short l = Util.getShort(buffer, (short)(readIdx + 1));
            readIdx += 3;
            for (short i = 0; i < l; i++) {
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s >= 0x0080 && s <= 0x0097) {
            readIdx++;
            for (short i = 0; i < (short)(s - 0x0080); i++) {
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s >= 0x00A0 && s <= 0x00B7) {
            readIdx++;
            for (short i = 0; i < (short)(s - 0x00A0); i++) {
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        if (s == 0x00B8) {
            short l = ub(buffer[++readIdx]);
            readIdx++;
            for (short i = 0; i < l; i++) {
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
                readIdx = consumeAnyEntity(apdu, buffer, readIdx, lc);
            }
            return readIdx;
        }
        return readIdx;
    }
    private short consumeMapAndGetID(APDU apdu, byte[] buffer, short readIdx, short lc, boolean byteString, boolean checkTypePublicKey, boolean checkAllFieldsText, boolean findName) {
        boolean foundTargetField = false;
        boolean foundType = false;
        boolean correctType = false;
        transientStorage.readyStoredVars();
        short mapDef = ub(buffer[readIdx++]);
        short mapEntryCount = 0;
        if ((mapDef & 0xF0) == 0xA0) {
            mapEntryCount = (short) (mapDef & 0x0F);
        } else if ((mapDef & 0xF0) == 0xB0 && mapDef < ub((byte) 0xB8)) {
            mapEntryCount = (short) ((mapDef & 0x0F) + 16);
        } else if (mapDef == (byte) 0xB8) {
            mapEntryCount = ub(buffer[readIdx++]);
        }
        for (short i = 0; i < mapEntryCount; i++) {
            final short keyDef = ub(buffer[readIdx++]);
            short keyLen = 0;
            if (keyDef == 0x0078) {
                keyLen = ub(buffer[readIdx++]);
            } else if (keyDef >= 0x0060 && keyDef < 0x0078) {
                keyLen = (short)(keyDef - 0x0060);
            }
            final boolean isId = (keyLen == 2 && buffer[readIdx] == 'i' && buffer[(short)(readIdx+1)] == 'd');
            final boolean isType = (keyLen == 4 && buffer[readIdx] == 't' && buffer[(short)(readIdx+1)] == 'y' && buffer[(short)(readIdx+2)] == 'p' && buffer[(short)(readIdx+3)] == 'e');
            final boolean isName = (keyLen == 4 && buffer[readIdx] == 'n' && buffer[(short)(readIdx+1)] == 'a' && buffer[(short)(readIdx+2)] == 'm' && buffer[(short)(readIdx+3)] == 'e');
            readIdx += keyLen;
            short valDef = ub(buffer[readIdx++]);
            short targetPos = readIdx;
            short valLen = 0;
            if (valDef == 0x0078 || valDef == 0x0058) {
                valLen = ub(buffer[readIdx++]);
                if (isId || isName) {
                    targetPos++;
                }
            } else if (valDef == 0x0079) {
                valLen = Util.getShort(buffer, readIdx);
                readIdx += 2;
            } else if (valDef >= 0x0060 && valDef < 0x0078) {
                valLen = (short)(valDef - 0x0060);
            } else if (valDef >= 0x0040 && valDef < 0x0058) {
                if (isType) {
                    foundType = true;
                    correctType = false;
                }
                valLen = (short) (valDef - 0x0040);
            } else {
                valLen = (short)(consumeAnyEntity(apdu, buffer, (short)(readIdx - 1), lc) - readIdx);
            }
            if (isId) {
                if (!findName) {
                    foundTargetField = true;
                    transientStorage.setStoredVars(targetPos, (byte) valLen);
                }
            }
            if (isName) {
                if (findName) {
                    foundTargetField = true;
                    transientStorage.setStoredVars(targetPos, (byte) valLen);
                }
            }
            if (!foundType && isType && checkTypePublicKey) {
                foundType = true;
                correctType = valLen == (short) CannedCBOR.PUBLIC_KEY_TYPE.length && Util.arrayCompare(buffer, readIdx, CannedCBOR.PUBLIC_KEY_TYPE, (short) 0, valLen) == 0;
            }
            readIdx += valLen;
        }
        if (!foundTargetField) {
            transientStorage.setStoredVars((short) 0, (byte) 0);
        }
        if (checkTypePublicKey) {
            if (!correctType) {
                transientStorage.readyStoredVars();
            }
        }
        return readIdx;
    }
    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            handleAppletSelect(apdu);
            return;
        }
        final byte[] apduBytes = apdu.getBuffer();
        final short cla_ins = Util.getShort(apduBytes, ISO7816.OFFSET_CLA);
        final short p1_p2 = Util.getShort(apduBytes, ISO7816.OFFSET_P1);
        
        if (cla_ins == (short) 0x00A4 && p1_p2 == (short) 0x0400) {
            handleAppletSelect(apdu);
            return;
        }
        if (cla_ins == 0x00C0 || cla_ins == (short) 0x80C0) {
            streamOutgoingContinuation(apdu, apduBytes, true);
            return;
        }
        
        final short amtRead = apdu.setIncomingAndReceive();
        final short lc = apdu.getIncomingLength();
        short lcEffective = (short)(lc + 1);
        byte cmdByte = apduBytes[apdu.getOffsetCdata()];
        if (cmdByte != FIDOConstants.CMD_LARGE_BLOBS) {
            transientStorage.clearOutgoingContinuation();
        }
        short chainingReadOffset = transientStorage.getChainIncomingReadOffset();
        if (chainingReadOffset > 0) {
            cmdByte = bufferMem[0];
            lcEffective += chainingReadOffset;
        }
        if (cmdByte != FIDOConstants.CMD_CREDENTIAL_MANAGEMENT && cmdByte != FIDOConstants.CMD_CREDENTIAL_MANAGEMENT_PREVIEW) {
            transientStorage.clearIterationPointers();
        }
        if (cmdByte != FIDOConstants.CMD_GET_NEXT_ASSERTION) {
            transientStorage.clearAssertIterationPointer();
        }

        bufferManager.initializeAPDU(apdu);
        byte[] reqBuffer;
        switch (cmdByte) {
            case FIDOConstants.CMD_GET_INFO:
                sendAuthInfo(apdu);
                break;
            case FIDOConstants.CMD_GET_ASSERTION:
                reqBuffer = fullyReadReq(apdu, lc, amtRead, true);
                getAssertion(apdu, lcEffective, reqBuffer);
                break;
        }
        transientStorage.resetChainIncomingReadOffset();
    }
    private byte[] getCurrentLargeBlobStore() {
        if (largeBlobStoreIndex == 0) {
            return largeBlobStoreA;
        }
        return largeBlobStoreB;
    }
    private boolean streamOutgoingContinuation(APDU apdu, byte[] apduBytes, boolean chaining) {
        if (transientStorage.getOutgoingContinuationRemaining() == 0) return true;
        short outgoingOffset = transientStorage.getOutgoingContinuationOffset();
        short outgoingRemaining = transientStorage.getOutgoingContinuationRemaining();
        short remainingValidInBufMem = outgoingRemaining;
        short chunkSize = (short)(APDU.getOutBlockSize() - 2);
        if (chaining) {
            final short requestedChunkSize = apdu.setOutgoing();
            if (requestedChunkSize < chunkSize) chunkSize = requestedChunkSize;
        }
        final short writeSize = chunkSize <= outgoingRemaining ? chunkSize : outgoingRemaining;
        if (chaining) apdu.setOutgoingLength(writeSize);
        short chunkToWrite = writeSize;
        if (remainingValidInBufMem > 0) {
            short writeFromBufMem = remainingValidInBufMem;
            if (writeFromBufMem > chunkToWrite) writeFromBufMem = chunkToWrite;
            Util.arrayCopyNonAtomic(bufferMem, outgoingOffset, apduBytes, (short) 0, writeFromBufMem);
            chunkToWrite -= writeFromBufMem;
        }
        apdu.sendBytes((short) 0, writeSize);
        outgoingOffset += writeSize;
        outgoingRemaining -= writeSize;
        transientStorage.setOutgoingContinuation(outgoingOffset, outgoingRemaining);
        if (chaining) transientStorage.clearOutgoingContinuation();
        return false;
    }
    private void handleAppletSelect(APDU apdu) {
        if (bufferManager == null) {
            apdu.setIncomingAndReceive();
            initTransientStorage(apdu);
            short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            final short transientMem = availableMem >= MAX_RAM_SCRATCH_SIZE ? MAX_RAM_SCRATCH_SIZE : availableMem;
            JCSystem.beginTransaction();
            boolean ok = false;
            try {
                bufferManager = new BufferManager(transientMem, FLASH_SCRATCH_SIZE);
                bufferManager.initializeAPDU(apdu);
                random.generateData(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length);
                lowSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
                random.generateData(wrappingKeySpace, (short) 0, (short) wrappingKeySpace.length);
                highSecurityWrappingKey.setKey(wrappingKeySpace, (short) 0);
                random.generateData(wrappingKeyValidation, (short) 0, (short) 32);
                hmacSha256(apdu, wrappingKeySpace, (short) 0, wrappingKeyValidation, (short) 0, (short) 32, wrappingKeyValidation, (short) 32);                
                ok = true;
            } finally {
                if (ok) {
                    JCSystem.commitTransaction();
                } else {
                    JCSystem.abortTransaction();
                }
            }
        }
        bufferManager.clear();
        if (alwaysUv || attestationData == null || filledAttestationData < attestationData.length) {
            sendByteArray(apdu, CannedCBOR.FIDO_2_RESPONSE, (short) CannedCBOR.FIDO_2_RESPONSE.length);
        } else {
            sendByteArray(apdu, CannedCBOR.U2F_V2_RESPONSE, (short) CannedCBOR.U2F_V2_RESPONSE.length);
        }
    }
    private short packCredentialId(byte[] credBuffer, short credOffset, byte[] writeBuffer, short writeOffset) {
        writeBuffer[writeOffset++] = (byte) 0xA2; 
        writeBuffer[writeOffset++] = 0x62; 
        writeBuffer[writeOffset++] = 0x69; 
        writeBuffer[writeOffset++] = 0x64; 
        writeOffset = encodeIntLenTo(writeBuffer, writeOffset, CREDENTIAL_ID_LEN, true);
        writeOffset = Util.arrayCopyNonAtomic(credBuffer, credOffset, writeBuffer, writeOffset, CREDENTIAL_ID_LEN);
        writeBuffer[writeOffset++] = 0x64; 
        writeBuffer[writeOffset++] = 0x74; 
        writeBuffer[writeOffset++] = 0x79; 
        writeBuffer[writeOffset++] = 0x70; 
        writeBuffer[writeOffset++] = 0x65; 
        writeOffset = encodeIntLenTo(writeBuffer, writeOffset, (short) CannedCBOR.PUBLIC_KEY_TYPE.length, false);
        writeOffset = Util.arrayCopyNonAtomic(CannedCBOR.PUBLIC_KEY_TYPE, (short) 0, writeBuffer, writeOffset, (short) CannedCBOR.PUBLIC_KEY_TYPE.length);
        return writeOffset;
    }
    private short encodeIntTo(byte[] outBuf, short writeOffset, byte v) {
        if (v < 24) {
            outBuf[writeOffset++] = v;
        } else {
            outBuf[writeOffset++] = 0x18; 
            outBuf[writeOffset++] = v;
        }
        return writeOffset;
    }
    private void sendAuthInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        short numOptions = 0x00B0;
        boolean includeMaxMsgSize = bufferMem.length != 1024;
        if (includeMaxMsgSize) numOptions++;
        buffer[offset++] = FIDOConstants.CTAP2_OK;
        buffer[offset++] = (byte) numOptions; 
        buffer[offset++] = 0x01; 
        if (alwaysUv || attestationData == null || filledAttestationData < attestationData.length) {
            offset = Util.arrayCopyNonAtomic(CannedCBOR.VERSIONS_WITHOUT_U2F, (short) 0, buffer, offset, (short) CannedCBOR.VERSIONS_WITHOUT_U2F.length);
        } else {
            offset = Util.arrayCopyNonAtomic(CannedCBOR.VERSIONS_WITH_U2F, (short) 0, buffer, offset, (short) CannedCBOR.VERSIONS_WITH_U2F.length);
        }
        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_START, (short) 0, buffer, offset, (short) CannedCBOR.AUTH_INFO_START.length);
        offset = Util.arrayCopyNonAtomic(aaguid, (short) 0, buffer, offset, (short) aaguid.length);
        buffer[offset++] = 0x04; 
        buffer[offset++] = (byte) 0xAB; 
        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_SECOND, (short) 0, buffer, offset, (short) CannedCBOR.AUTH_INFO_SECOND.length);
        buffer[offset++] = (byte)(alwaysUv ? 0xF5 : 0xF4); 
        offset = Util.arrayCopyNonAtomic(CannedCBOR.AUTH_INFO_THIRD, (short) 0, buffer, offset, (short) CannedCBOR.AUTH_INFO_THIRD.length);
        buffer[offset++] = (byte)(pinSet ? 0xF5 : 0xF4); 
        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.LARGE_BLOBS.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.LARGE_BLOBS, (short) 0, buffer, offset, (short) CannedCBOR.LARGE_BLOBS.length);
        buffer[offset++] = (byte) 0xF5; 
        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.PIN_UV_AUTH_TOKEN.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.PIN_UV_AUTH_TOKEN, (short) 0, buffer, offset, (short) CannedCBOR.PIN_UV_AUTH_TOKEN.length);
        buffer[offset++] = (byte) 0xF5; 
        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.SET_MIN_PIN_LENGTH.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.SET_MIN_PIN_LENGTH, (short) 0, buffer, offset, (short) CannedCBOR.SET_MIN_PIN_LENGTH.length);
        buffer[offset++] = (byte) 0xF5; 
        offset = encodeIntLenTo(buffer, offset, (short) CannedCBOR.MAKE_CRED_UV_NOT_REQD.length, false);
        offset = Util.arrayCopyNonAtomic(CannedCBOR.MAKE_CRED_UV_NOT_REQD, (short) 0, buffer, offset, (short) CannedCBOR.MAKE_CRED_UV_NOT_REQD.length);
        buffer[offset++] = (byte)(LOW_SECURITY_MAXIMUM_COMPLIANCE && !alwaysUv ? 0xF5 : 0xF4); 
        if (includeMaxMsgSize) {
            buffer[offset++] = 0x05; 
            buffer[offset++] = 0x19; 
            offset = Util.setShort(buffer, offset, (short) bufferMem.length);
        }
        buffer[offset++] = 0x06; 
        buffer[offset++] = (byte) 0x82; 
        buffer[offset++] = 0x02; 
        buffer[offset++] = 0x01; 
        buffer[offset++] = 0x07; 
        buffer[offset++] = 0x17; 
        final short amountInApduBuf = offset;
        final byte approximateKeyCount = getApproximateRemainingKeyCount();
        buffer = bufferMem;
        offset = 0;
        buffer[offset++] = 0x08; 
        offset = encodeIntTo(buffer, offset, (byte) CREDENTIAL_ID_LEN); 
        buffer[offset++] = 0x0A; 
        offset = Util.arrayCopyNonAtomic(CannedCBOR.ES256_ALG_TYPE, (short) 0, buffer, offset, (short) CannedCBOR.ES256_ALG_TYPE.length); 
        buffer[offset++] = 0x0B; 
        buffer[offset++] = 0x19; 
        offset = Util.setShort(buffer, offset, (short) getCurrentLargeBlobStore().length); 
        buffer[offset++] = 0x0C; 
        buffer[offset++] = (byte)(forcePinChange ? 0xF5 : 0xF4); 
        buffer[offset++] = 0x0D; 
        offset = encodeIntTo(buffer, offset, minPinLength); 
        buffer[offset++] = 0x0E; 
        offset = encodeIntTo(buffer, offset, FIRMWARE_VERSION); 
        buffer[offset++] = 0x0F; 
        offset = encodeIntTo(buffer, offset, MAX_CRED_BLOB_LEN); 
        buffer[offset++] = 0x10; 
        offset = encodeIntTo(buffer, offset, MAX_RP_IDS_MIN_PIN_LENGTH); 
        buffer[offset++] = 0x12; 
        buffer[offset++] = 0x19; 
        offset = Util.setShort(buffer, offset, (short) 0x0200); 
        buffer[offset++] = 0x14; 
        offset = encodeIntTo(buffer, offset, approximateKeyCount);
        sendNoCopy(apdu, amountInApduBuf);
        setupChainedResponse((short) 0, offset);
    }
    private static byte getApproximateRemainingKeyCount() {
        short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
        if (availableMem < 0) availableMem = Short.MAX_VALUE;
        final short approx = (short)(availableMem / APPROXIMATE_STORAGE_PER_RESIDENT_KEY);
        return (byte)(approx > 100 ? 100 : approx);
    }
    private void throwException(short swCode, boolean clearIteration) {
        if (clearIteration) transientStorage.clearIterationPointers();
        bufferManager.clear();
        ecKeyPair.getPrivate().clearKey();
        ISOException.throwIt(swCode);
    }
    public void deselect() {
        transientStorage.clearOnDeselect();
        permissionsRpId[0] = 0x00;
    }
    private ECPrivateKey getECPrivKey(boolean forceAllowTransient, boolean allowDeselectMemory) {
        if (forceAllowTransient) {
            if (allowDeselectMemory) {
                try {
                    return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
                } catch (CryptoException e) {
                }
            }
            try {
                return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
            } catch (CryptoException e) {
            }
        }
        return (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    }
    private AESKey getPersistentAESKey() {
        return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }
    private AESKey getTransientAESKey() {
        return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    }
    @SuppressWarnings("unused")
    public static void install(byte[] array, short offset, byte length) throws ISOException {
        if (Constants.DEBUG) System.out.println("FIDO2Applet install");
        short pos = offset;
        // find AID
        byte lenAID = array[pos++];
        short offAID = pos;
        FIDO2Applet applet = new FIDO2Applet(array, (short)0, (byte)0);
    
        applet.register(array, offAID, lenAID);
    }
    @SuppressWarnings("unused")
    private FIDO2Applet(byte[] array, short offset, byte length) {
        LOW_SECURITY_MAXIMUM_COMPLIANCE = true;
        FORCE_ALWAYS_UV = false;
        MAX_CRED_BLOB_LEN = 32;
        short largeBlobStoreSize = 1024;
        MAX_RAM_SCRATCH_SIZE = 512;
        BUFFER_MEM_SIZE = 1024;
        FLASH_SCRATCH_SIZE = 1024;
        final short initOffset = offset;
        alwaysUv = FORCE_ALWAYS_UV;
        pinKDFSalt = new byte[28];
        wrappingKeySpace = new byte[32];
        wrappingKeyValidation = new byte[64];
        hmacWrapperBytesUV = new byte[32];
        hmacWrapperBytesNoUV = new byte[32];
        credentialVerificationKey = new byte[32];
        highSecurityWrappingIV = new byte[IV_LEN];
        largeBlobStoreA = new byte[largeBlobStoreSize];
        Util.arrayCopyNonAtomic(CannedCBOR.INITIAL_LARGE_BLOB_ARRAY, (short) 0, largeBlobStoreA, (short) 0, (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length);
        largeBlobStoreB = new byte[largeBlobStoreSize];
        Util.arrayCopyNonAtomic(CannedCBOR.INITIAL_LARGE_BLOB_ARRAY, (short) 0, largeBlobStoreB, (short) 0, (short) CannedCBOR.INITIAL_LARGE_BLOB_ARRAY.length);
        highSecurityWrappingKey = getTransientAESKey(); 
        lowSecurityWrappingKey = getPersistentAESKey(); 
        counter = new SigOpCounter();
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        transientStorage = new TransientStorage();
        final short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        boolean authenticatorKeyInRam = availableMem >= 148; 
        boolean ecPairInRam = availableMem >= 180; 
        initAuthenticatorKey(authenticatorKeyInRam);
        initCredKey(ecPairInRam);
    }
    private void initAuthenticatorKey(boolean authenticatorKeyInRam) {
        authenticatorKeyAgreementKey = new KeyPair((ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false), getECPrivKey(authenticatorKeyInRam, false));
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPrivate());
        P256Constants.setCurve((ECKey) authenticatorKeyAgreementKey.getPublic());
    }
    private void initCredKey(boolean ecPairInRam) {
        ecKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                getECPrivKey(ecPairInRam, true)
        );
        P256Constants.setCurve((ECKey) ecKeyPair.getPrivate());
        P256Constants.setCurve((ECKey) ecKeyPair.getPublic());
    }
    private byte[] getTempOrFlashByteBuffer(short len, boolean inRAM) {
        if (inRAM) return JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        return new byte[len];
    }
    private void initTransientStorage(APDU apdu) {
        final boolean apduBufferIsLarge = apdu.getBuffer().length >= 2048;
        short availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        if ((apduBufferIsLarge && availableMem > 64) || availableMem > 300) {
            if (authenticatorKeyAgreementKey.getPrivate().getType() == KeyBuilder.TYPE_EC_FP_PRIVATE) {
                initAuthenticatorKey(true);
                P256Constants.setCurve((ECPrivateKey) authenticatorKeyAgreementKey.getPrivate());
                P256Constants.setCurve((ECPublicKey) authenticatorKeyAgreementKey.getPublic());
            }
            if (ecKeyPair.getPrivate().getType() == KeyBuilder.TYPE_EC_FP_PRIVATE) {
                initCredKey(true);
                P256Constants.setCurve((ECPrivateKey) ecKeyPair.getPrivate());
                P256Constants.setCurve((ECPublicKey) ecKeyPair.getPublic());
            }
            availableMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            try {
                JCSystem.requestObjectDeletion();
            } catch (Exception e) {
            }
        }
        short targetMemAmount = 99; 
        if (apduBufferIsLarge) targetMemAmount = 3; 
        final boolean pinTokenInRam = availableMem >= (short)(targetMemAmount + 32);
        if (pinTokenInRam) targetMemAmount += 32;
        final boolean sharedSecretVerifyInRam = availableMem >= (short)(targetMemAmount + 32);
        if (sharedSecretVerifyInRam) targetMemAmount += 32;
        final boolean permRpIdInRam = availableMem >= (short)(targetMemAmount + RP_HASH_LEN + 1);
        if (permRpIdInRam) {
            targetMemAmount += RP_HASH_LEN;
            targetMemAmount++;
        }
        permissionsRpId = getTempOrFlashByteBuffer((short)(RP_HASH_LEN + 1), permRpIdInRam);
        if (availableMem >= (short)(targetMemAmount + 32)) targetMemAmount += 32;
        if (availableMem >= (short)(targetMemAmount + 32)) targetMemAmount += 32;
        boolean requestBufferInRam = availableMem >= (short)(targetMemAmount + BUFFER_MEM_SIZE);
        if (requestBufferInRam) targetMemAmount += BUFFER_MEM_SIZE;
        bufferMem = getTempOrFlashByteBuffer(BUFFER_MEM_SIZE, requestBufferInRam);
        random.generateData(pinKDFSalt, (short) 0, (short) pinKDFSalt.length);
        random.generateData(highSecurityWrappingIV, (short) 0, (short) highSecurityWrappingIV.length);
        random.generateData(hmacWrapperBytesUV, (short) 0, (short) hmacWrapperBytesUV.length);
        random.generateData(hmacWrapperBytesNoUV, (short) 0, (short) hmacWrapperBytesNoUV.length);
        random.generateData(credentialVerificationKey, (short) 0, (short) credentialVerificationKey.length);
    }
}