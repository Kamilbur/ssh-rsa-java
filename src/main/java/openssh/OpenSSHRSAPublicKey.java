package openssh;

import openssh.types.*;

import java.math.BigInteger;


public class OpenSSHRSAPublicKey extends OpenSSHPublicKey {

    private OpenSSHMPInt modulus;
    private OpenSSHMPInt publicExponent;

    private final byte[] expectedAlgorithmIdentifier = "ssh-rsa".getBytes();

    public OpenSSHRSAPublicKey(byte[] body) throws DeserializationException {
        try {
            deserialize(body);
        } catch (IndexOutOfBoundsException ignored) {
            throw new DeserializationException("Passed data does not match key data format");
        }
    }

    @Override
    void deserialize(byte[] body) throws DeserializationException {
        OpenSSHDeserializer deserializer = new OpenSSHDeserializer(body);
        byte[] actualAlgorithmIdentifier = deserializer.readBytes(expectedAlgorithmIdentifier.length);
        checkAlgorithmIdentifier(actualAlgorithmIdentifier, expectedAlgorithmIdentifier);
        publicExponent = deserializer.readMPInt();
        modulus = deserializer.readMPInt();
    }

    public BigInteger getModulus() {
        return modulus.getValue();
    }

    public BigInteger getPublicExponent() {
        return publicExponent.getValue();
    }
}
