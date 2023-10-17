package openssh;

import java.math.BigInteger;

public class OpenSSHRSAPublicKey extends OpenSSHPublicKey {

    private BigInteger modulus;
    private BigInteger publicExponent;

    private final byte[] expectedAlgorithmIdentifier = "ssh-rsa".getBytes();

    public OpenSSHRSAPublicKey(byte[] body) throws DeserializationException {
        deserialize(body);
    }

    @Override
    void deserialize(byte[] body) throws DeserializationException {
        OpenSSHDeserializer deserializer = new OpenSSHDeserializer(body);
        checkAlgorithmIdentifier(deserializer.readBytes(expectedAlgorithmIdentifier.length), expectedAlgorithmIdentifier);
        publicExponent = deserializer.readMPInt().getValue();
        modulus = deserializer.readMPInt().getValue();
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }
}
