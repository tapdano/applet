# TapDano Java Card Applet

## About the Project
The **TapDano** project integrates Cardano blockchain transactions with smart card technology.
This repository hosts a Java Card applet designed to facilitate secure and efficient communication between the physical world and the Cardano blockchain.
It leverages the **CTAP** (Client To Authenticator Protocol) from the **FIDO Alliance** and **NDEF** (NFC Data Exchange Format) for communication, using the **Ed25519** algorithm for generating, storing, and signing transactions, ensuring high security and compatibility with the Cardano blockchain.

## Key Features
- Secure communication using CTAP and NDEF protocols.
- Transaction signing with the Ed25519 algorithm.
- Secure storage for private keys.

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
