package tapdano;

public abstract class FIDOConstants {
    public static final byte CMD_MAKE_CREDENTIAL = 0x01;
    public static final byte CMD_GET_ASSERTION = 0x02;
    public static final byte CMD_GET_INFO = 0x04;
    public static final byte CMD_CLIENT_PIN = 0x06;
    public static final byte CMD_RESET = 0x07;
    public static final byte CMD_GET_NEXT_ASSERTION = 0x08;
    public static final byte CMD_CREDENTIAL_MANAGEMENT = 0x0A;
    public static final byte CMD_CREDENTIAL_MANAGEMENT_PREVIEW = 0x41;

    public static final byte CLIENT_PIN_GET_RETRIES = 0x01;
    public static final byte CLIENT_PIN_GET_KEY_AGREEMENT = 0x02;
    public static final byte CLIENT_PIN_SET_PIN = 0x03;
    public static final byte CLIENT_PIN_CHANGE_PIN = 0x04;
    public static final byte CLIENT_PIN_GET_PIN_TOKEN = 0x05;

    public static final byte CRED_MGMT_GET_CREDS_META = 0x01;
    public static final byte CRED_MGMT_ENUMERATE_RPS_BEGIN = 0x02;
    public static final byte CRED_MGMT_ENUMERATE_RPS_NEXT = 0x03;
    public static final byte CRED_MGMT_ENUMERATE_CREDS_BEGIN = 0x04;
    public static final byte CRED_MGMT_ENUMERATE_CREDS_NEXT = 0x05;
    public static final byte CRED_MGMT_DELETE_CRED = 0x06;
    public static final byte CRED_MGMT_UPDATE_USER_INFO = 0x07;

    public static final byte CTAP2_OK = 0x00; // 	Indicates successful response.
    public static final byte CTAP1_ERR_INVALID_COMMAND = 0x01; //	 	The command is not a valid CTAP command.
    public static final byte CTAP1_ERR_INVALID_PARAMETER = 0x02; //	 	The command included an invalid parameter.
    public static final byte CTAP1_ERR_INVALID_LENGTH = 0x03; //	 	Invalid message or item length.
    public static final byte CTAP1_ERR_INVALID_SEQ = 0x04; //	 	Invalid message sequencing.
    public static final byte CTAP1_ERR_TIMEOUT = 0x05; //	 	Message timed out.
    public static final byte CTAP1_ERR_CHANNEL_BUSY = 0x06; //	 	Channel busy.
    public static final byte CTAP1_ERR_LOCK_REQUIRED = 0x0A; //	 	Command requires channel lock.
    public static final byte CTAP1_ERR_INVALID_CHANNEL = 0x0B; //	 	Command not allowed on this cid.
    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11; //	 	Invalid/unexpected CBOR error.
    public static final byte CTAP2_ERR_INVALID_CBOR = 0x12; //	 	Error when parsing CBOR.
    public static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14; //	 	Missing non-optional parameter.
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = 0x15; //	 	Limit for number of items exceeded.
    public static final byte CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16; //	 	Unsupported extension.
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19; //	 	Valid credential found in the exclude list.
    public static final byte CTAP2_ERR_PROCESSING = 0x21; //	 	Processing (Lengthy operation is in progress).
    public static final byte CTAP2_ERR_INVALID_CREDENTIAL = 0x22; //	 	Credential not valid for the authenticator.
    public static final byte CTAP2_ERR_USER_ACTION_PENDING = 0x23; //	 	Authentication is waiting for user interaction.
    public static final byte CTAP2_ERR_OPERATION_PENDING = 0x24; //	 	Processing, lengthy operation is in progress.
    public static final byte CTAP2_ERR_NO_OPERATIONS = 0x25; //	 	No request is pending.
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26; //	 	Authenticator does not support requested algorithm.
    public static final byte CTAP2_ERR_OPERATION_DENIED = 0x27; //	 	Not authorized for requested operation.
    public static final byte CTAP2_ERR_KEY_STORE_FULL = 0x28; //	 	Internal key storage is full.
    public static final byte CTAP2_ERR_NOT_BUSY = 0x29; //	 	Authenticator cannot cancel as it is not busy.
    public static final byte CTAP2_ERR_NO_OPERATION_PENDING = 0x2A; //	 	No outstanding operations.
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B; //	 	Unsupported option.
    public static final byte CTAP2_ERR_INVALID_OPTION = 0x2C; //	 	Not a valid option for current operation.
    public static final byte CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D; //	 	Pending keep alive was cancelled.
    public static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2E; //	 	No valid credentials provided.
    public static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F; //	 	Timeout waiting for user interaction.
    public static final byte CTAP2_ERR_NOT_ALLOWED = 0x30; //	 	Continuation command, such as, authenticatorGetNextAssertion not allowed.
    public static final byte CTAP2_ERR_PIN_INVALID = 0x31; //	 	PIN Invalid.
    public static final byte CTAP2_ERR_PIN_BLOCKED = 0x32; //	 	PIN Blocked.
    public static final byte CTAP2_ERR_PIN_AUTH_INVALID = 0x33; //	 	PIN authentication,pinAuth, verification failed.
    public static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34; //	 	PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    public static final byte CTAP2_ERR_PIN_NOT_SET = 0x35; //	 	No PIN has been set.
    public static final byte CTAP2_ERR_PIN_REQUIRED = 0x36; //	 	PIN is required for the selected operation.
    public static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37; //	 	PIN policy violation. Currently only enforces minimum length.
    public static final byte CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38; //	 	pinToken expired on authenticator.
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = 0x39; //	 	Authenticator cannot handle this request due to memory constraints.
    public static final byte CTAP2_ERR_ACTION_TIMEOUT = 0x3A; //	 	The current operation has timed out.
    public static final byte CTAP2_ERR_UP_REQUIRED = 0x3B; //	 	User presence is required for the requested operation.
    public static final byte CTAP1_ERR_OTHER = 0x7F; //	 	Other unspecified error.
}
