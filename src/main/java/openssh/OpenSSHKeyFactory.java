package openssh;

import java.util.*;
import java.util.stream.Stream;

public class OpenSSHKeyFactory {
    private static final List<String> supported = Stream.of(
            "ssh-rsa"
    ).sorted(Comparator.comparingInt(String::length)).toList().reversed();

    public static OpenSSHPublicKey generatePublic(byte[] body) throws DeserializationException, UnsupportedOperationException {
        OpenSSHDeserializer deserializer = new OpenSSHDeserializer(body);

        for (String algorithmIdentifier : supported) {
            try {
                byte[] identifierBytes = algorithmIdentifier.getBytes();
                byte[] actualBytes = deserializer.probeBytesSafe(identifierBytes.length);
                if (Arrays.equals(actualBytes, identifierBytes)) {
                    return generatePublicFromAlgorithmIdentifier(algorithmIdentifier, body);
                }
            } catch (IndexOutOfBoundsException ignored) {
                throw new DeserializationException("Passed data does not match key data format");
            }
        }
        throw new UnsupportedOperationException();
    }

    private static OpenSSHPublicKey generatePublicFromAlgorithmIdentifier(String algorithmIdentifier, byte[] body) throws DeserializationException, UnsupportedOperationException {
        switch (algorithmIdentifier) {
            case "ssh-rsa": return new OpenSSHRSAPublicKey(body);
            default: throw new UnsupportedOperationException();
        }
    }
}
