package openssh;

import openssh.types.OpenSSHMPInt;
import openssh.types.OpenSSHString;
import openssh.types.OpenSSHUInt32;
import openssh.types.OpenSSHUInt64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedList;


public class OpenSSHRSACertificate {
    private final byte[] format;
    private final byte[] body;

    /*
     * Value encoding according to
     * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
     * For more detailed descriptions of data types used see RFC4251 Section 5.
     */
    private OpenSSHString keyType;
    private OpenSSHString nonce;
    private OpenSSHMPInt exponent;
    private OpenSSHMPInt publicModulus;
    private OpenSSHUInt64 serial;
    private OpenSSHUInt32 type;
    private OpenSSHString keyId;
    private LinkedList<OpenSSHString> validPrincipals;
    private OpenSSHUInt64 validAfter;
    private OpenSSHUInt64 validBefore;
    private OpenSSHString criticalOptions;
    private OpenSSHString extensions;
    private OpenSSHString reserved;
    private OpenSSHString signatureKey;
    private OpenSSHString signature;

    public OpenSSHRSACertificate(String cert) {
        String[] parts = cert.trim().split(" ");
        format = parts[0].getBytes(StandardCharsets.UTF_8);
        body = Base64.getDecoder().decode(parts[1].getBytes(StandardCharsets.UTF_8));
        decode();
    }

    private void decode() {
        OpenSSHKeyBytesDecoder bytesDecoder = new OpenSSHKeyBytesDecoder(body);
        keyType = bytesDecoder.readString();
        nonce = bytesDecoder.readString();
        exponent = bytesDecoder.readMPInt();
        publicModulus = bytesDecoder.readMPInt();
        serial = bytesDecoder.readUInt64();
        type = bytesDecoder.readUInt32();
        keyId = bytesDecoder.readString();

        byte[] principals = bytesDecoder.readString().getValue();
        OpenSSHKeyBytesDecoder principalsDecoder = new OpenSSHKeyBytesDecoder(principals);
        validPrincipals = new LinkedList<>();
        while ( ! principalsDecoder.isEmpty()) {
            validPrincipals.add(principalsDecoder.readString());
        }

        validAfter = bytesDecoder.readUInt64();
        validBefore = bytesDecoder.readUInt64();
        criticalOptions = bytesDecoder.readString();
        extensions = bytesDecoder.readString();
        reserved = bytesDecoder.readString();
        signatureKey = bytesDecoder.readString();
        signature = bytesDecoder.readString();
    }

    public boolean isValid() {
        BigInteger now = BigInteger.valueOf(Instant.now().getEpochSecond());
        BigInteger after = validAfter.getValue();
        BigInteger before = validBefore.getValue();
        return after.compareTo(now) < 0 && before.compareTo(now) > 0;
    }

    public OpenSSHString getKeyType() {
        return keyType;
    }

    public OpenSSHString getNonce() {
        return nonce;
    }

    public OpenSSHMPInt getExponent() {
        return exponent;
    }

    public OpenSSHMPInt getPublicModulus() {
        return publicModulus;
    }

    public OpenSSHUInt64 getSerial() {
        return serial;
    }

    public OpenSSHUInt32 getType() {
        return type;
    }

    public OpenSSHString getKeyId() {
        return keyId;
    }

    public LinkedList<OpenSSHString> getValidPrincipals() {
        return validPrincipals;
    }

    public OpenSSHUInt64 getValidAfter() {
        return validAfter;
    }

    public OpenSSHUInt64 getValidBefore() {
        return validBefore;
    }

    public OpenSSHString getCriticalOptions() {
        return criticalOptions;
    }

    public OpenSSHString getExtensions() {
        return extensions;
    }

    public OpenSSHString getReserved() {
        return reserved;
    }

    public OpenSSHString getSignatureKey() {
        return signatureKey;
    }

    public OpenSSHString getSignature() {
        return signature;
    }
}