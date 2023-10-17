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
            byte[] identifierBytes = algorithmIdentifier.getBytes();
            byte[] actualBytes = deserializer.probeBytes(identifierBytes.length);
            if (Arrays.equals(actualBytes, identifierBytes)) {
                return generatePublic2(algorithmIdentifier, body);
            }
        }
        throw new UnsupportedOperationException();
    }

    private static OpenSSHPublicKey generatePublic2(String algorithmIdentifier, byte[] body) throws DeserializationException {
        switch (algorithmIdentifier) {
            case "ssh-rsa": return new OpenSSHRSAPublicKey(body);
            default: throw new UnsupportedOperationException();
        }
    }
}
