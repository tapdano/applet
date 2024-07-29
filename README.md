# TapDano Java Card Applet

## About the Project
The **TapDano** project integrates Cardano blockchain transactions with smart card technology.

This repository hosts a Java Card applet designed to facilitate secure and efficient communication between the physical world and the Cardano blockchain.

It leverages the **CTAP** (Client To Authenticator Protocol) from the **FIDO Alliance** and **NDEF** (NFC Data Exchange Format) for communication, using the **Ed25519** algorithm for generating, storing, and signing transactions, ensuring high security and compatibility with the Cardano blockchain.

## Types of TapDano Tags
 - `Soulbound` - non-extractable private key
 - `Extractable` - extractable private key

## Standard Return Structure
This applet provides a standard return format, regardless of whether it was just read or received a method call. The format is as follows:
 - byte[2] - 0x5444 ("TD") - to indicate a card with TapDano firmware;
 - byte[2] - version (the current is 0x0101)
 - byte[1] - IsTagBurned (0x00 = false, 0x01 = true)
 
If IsTagBurned = true:
 - byte[1] - Type (0x01 = Soulbound, 0x02 = Extractable)
 - byte[1] - Extract Locked (permanent lock of the private key extraction, default behavior in Soulbound tags)
 - byte[1] - PIN Locked (temporary lock with a PIN, 0x00 = false, 0x01 = true)
 - byte[32] - public or private key (if the tag is Extractable and not permanently or temporarily locked)
 - byte[28] - PolicyId, which can be set using the SetPolicyId method
  
If there is no temporary lock (via PIN):
 - byte[32] - two-factor key (derived from the tag's private key)
 - byte[32] - last performed signature

## Key Features
- Secure communication using APDU, CSAP (WebAuthn) or NEFF (WebNBF) protocols.
- Transaction signing with the Ed25519 algorithm.
- The tag can be temporarily locked using a PIN, preventing access to the private key (only possible for Extractable tags), two-factor key, and the last signature.
- A key derived from the tag's private key can be used as a two-factor key for wallets or other apps.
- Secure storage for private keys.

## Methods

### **Burn Tag** (0xA1)
      Creates or restores a tag TapDano on a card
**Parameters:**
- `action`: byte
   - `0x01`: New
   - `0x02`: Restore
- `type` : byte
   - `0x01`: Soulbound
   - `0x02`: Extractable
- `privateKey`: byte[32] (only for restore)
- `publicKey`: byte[32] (only for restore)

---
### **Sign Data** (0xA2)
      Signs the received data and returns this signature in the "LAST_SIGNATURE" field
**Parameters:**
- `data`: byte[32] - larger sizes can also be passed, but the actual limit depends on the communication protocol used (APDH, CTAT, or NDEF)

---
### **Format Tag** (0xA3)
      Deletes the TapDano tag from a card, including keys and signatures related to this tag (can be enabled or disabled during installation)

---
### **Lock Tag** (0xA4)
      Permanently locks the extraction of the tag's private key. This is the default behavior for Soulbound tags and cannot be undone.

---
### **Pin Lock** (0xA5)
      Temporarily locks the extraction of the tag's private key, two-factor key, and the last signature using a PIN.
**Parameters:**
- `pin`: byte[4] (this number can be changed)

---
### **Pin Unlock** (0xA6)
      Unlocks the temporary lock via PIN
**Parameters:**
- `pin`: byte[4] (this number can be changed)

---
### **Set PolicyId** (0xA7)
      Stores the PolicyId
**Parameters:**
- `policyId`: byte[28]

---
### **Get Memory** (0xB0)
      Used only for memory tests during the development of this applet.

---
---
---

## APDU Examples
- `00A404000854617044616E6F0100` - Selects the TapDano Applet
- `00 A1 00 00 02 01 01` - Executes the `Burn Tag` method with parameters `action` and `type`:
   - `00` - CLA
   - `A1` - INS (Method `Burn Tag`)
   - `00` - P1
   - `00` - P2
   - `02` - Data Length
   - `01` - Parameter `action`
   - `01` - Parameter `type`

## Environment Setup and Building the application
1. **Download JavacardKit**: Obtain a copy of [JavacardKit version 3.2](https://www.oracle.com/java/technologies/javacard-sdk-downloads.html) (or jckit_303 if you prefer).
2. **Set Environment Variable**: Configure the `JC_HOME` environment variable to point to your JavacardKit directory.
   ```bash
   export JC_HOME=<path_to_your_jckit_directory>
   ```

3. **Run Gradle Build**: Execute the following command to build the JavaCard application, which will produce a `.cap` file for installation.
    ```bash
   ./gradlew buildJavaCard
    ```

## Contributing
Contributions are welcome! Feel free to:
- **Submit a Pull Request**: If you have a new feature idea or a bug fix.
- **Open an Issue**: For bug reports or feature suggestions.

Your contributions are greatly appreciated and help make TapDano better for everyone.