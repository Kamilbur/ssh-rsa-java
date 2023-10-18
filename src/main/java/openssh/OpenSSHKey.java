package openssh;

import java.util.Arrays;

abstract public class OpenSSHKey {

    abstract void deserialize(byte[] body) throws IndexOutOfBoundsException, DeserializationException;

    void checkAlgorithmIdentifier(byte[] actualKeyType, byte[] expectedKeyType) throws DeserializationException {
        if ( ! Arrays.equals(actualKeyType, expectedKeyType)) {
            throw new DeserializationException("Wrong key type field inside key.");
        }
    }
}
