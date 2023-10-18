package openssh;

import openssh.types.*;


import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedList;

public class OpenSSHRSACertificate extends OpenSSHCertificate {

    /*
     * Value encoding according to
     * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
     * For more detailed descriptions of data types used see RFC4251 Section 5.
     */
    private final byte[] expectedKeyType = "ssh-rsa-cert-v01@openssh.com".getBytes();
    private OpenSSHString nonce;
    private OpenSSHMPInt publicExponent;
    private OpenSSHMPInt modulus;
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

    public OpenSSHRSACertificate(String cert) throws DeserializationException {
        String[] parts = cert.trim().split(" ");
        try {
            byte[] keyBytes = parts[1].getBytes(StandardCharsets.UTF_8);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] body = decoder.decode(keyBytes);
            deserialize(body);
        } catch (IndexOutOfBoundsException ignored) {
            throw new DeserializationException("Passed data does not match certificate data format");
        }
    }

    void deserialize(byte[] body) throws IndexOutOfBoundsException, DeserializationException {
        OpenSSHDeserializer deserializer = new OpenSSHDeserializer(body);
        deserializer.skip4Bytes();
        byte[] actualKeyType = deserializer.readBytes(expectedKeyType.length);
        checkAlgorithmIdentifier(actualKeyType, expectedKeyType);
        nonce = deserializer.readString();
        publicExponent = deserializer.readMPInt();
        modulus = deserializer.readMPInt();
        serial = deserializer.readUInt64();
        type = deserializer.readUInt32();
        keyId = deserializer.readString();
        validPrincipals = deserializePrincipals(deserializer.readString().getValue());
        validAfter = deserializer.readUInt64();
        validBefore = deserializer.readUInt64();
        criticalOptions = deserializer.readString();
        extensions = deserializer.readString();
        reserved = deserializer.readString();
        signatureKey = deserializer.readString();
        signature = deserializer.readString();
    }

    private LinkedList<OpenSSHString> deserializePrincipals(byte[] principals) throws IndexOutOfBoundsException {
        OpenSSHDeserializer principalsDeserializer = new OpenSSHDeserializer(principals);
        LinkedList<OpenSSHString> validPrincipals = new LinkedList<>();
        while (!principalsDeserializer.isEmpty()) {
            validPrincipals.add(principalsDeserializer.readString());
        }
        return validPrincipals;
    }

    public boolean isValidTime() {
        BigInteger now = BigInteger.valueOf(Instant.now().getEpochSecond());
        BigInteger after = validAfter.getValue();
        BigInteger before = validBefore.getValue();
        return after.compareTo(now) < 0 && before.compareTo(now) > 0;
    }

    public boolean isValidPrivateKey(OpenSSHPrivateKeyV1 privateKey) {
        for (OpenSSHPublicKey key : privateKey.getPublicKeys()) {
            if (key instanceof OpenSSHRSAPublicKey && isValidRSAPublicKey((OpenSSHRSAPublicKey) key)) {
                return true;
            }
        }
        return false;
    }

    public boolean isValidRSAPublicKey(OpenSSHRSAPublicKey publicKey) {
        return publicKey.getModulus().equals(getModulus()) &&
                publicKey.getPublicExponent().equals(getPublicExponent());
    }

    public OpenSSHString getNonce() {
        return nonce;
    }

    public BigInteger getPublicExponent() {
        return publicExponent.getValue();
    }

    public BigInteger getModulus() {
        return modulus.getValue();
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