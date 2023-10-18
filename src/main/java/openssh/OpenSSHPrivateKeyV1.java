package openssh;

import openssh.types.OpenSSHMPInt;
import openssh.types.OpenSSHString;
import openssh.types.OpenSSHUInt32;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedList;

public class OpenSSHPrivateKeyV1 extends OpenSSHKey {
    private static final String MARK_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String MARK_END = "-----END OPENSSH PRIVATE KEY-----";
    private static final byte[] expectedAlgorithmIdentifier = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);

    /*
     * Specification is described in
     * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
     */
    private OpenSSHString ciphername;
    private OpenSSHString kdfname;
    private OpenSSHString kdfoptions;
    private LinkedList<OpenSSHPublicKey> publicKeys;
    private OpenSSHString encrypted;

    private final LinkedList<String> keyTypes = new LinkedList<>(Collections.singletonList(
            "ssh-rsa"
    ));

    public OpenSSHPrivateKeyV1(String key) throws DeserializationException {
        byte[] keyBytes = key.replace(MARK_BEGIN, "")
                .replace(MARK_END, "")
                .replace("\n", "")
                .getBytes(StandardCharsets.UTF_8);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] body = decoder.decode(keyBytes);
        try {
            deserialize(body);
        } catch (IndexOutOfBoundsException ignored) {
            throw new DeserializationException("Passed data does not match key data format");
        }
    }

    void deserialize(byte[] body) throws IndexOutOfBoundsException, DeserializationException {
        OpenSSHDeserializer deserializer = new OpenSSHDeserializer(body);
        byte[] actualAlgorithmIdentifier = deserializer.readBytes(expectedAlgorithmIdentifier.length);
        checkAlgorithmIdentifier(actualAlgorithmIdentifier, expectedAlgorithmIdentifier);
        ciphername = deserializer.readString();
        kdfname = deserializer.readString();
        kdfoptions = deserializer.readString();
        publicKeys = deserializePublicKeys(deserializer);
        encrypted = deserializer.readString();
    }

    private LinkedList<OpenSSHPublicKey> deserializePublicKeys(OpenSSHDeserializer deserializer) throws IndexOutOfBoundsException, DeserializationException {
        long numberOfPublicKeys = deserializer.readUInt32().getValue().longValue();
        LinkedList<OpenSSHPublicKey> publicKeys = new LinkedList<>();
        for (long i = 0; i < numberOfPublicKeys; i++) {
            OpenSSHString publicKeyString = deserializer.readString();
            publicKeys.add(deserializePublicKey(publicKeyString.getValue()));
        }
        return publicKeys;
    }

    private OpenSSHPublicKey deserializePublicKey(byte[] publicKeyBytes) throws IndexOutOfBoundsException, DeserializationException {
        OpenSSHDeserializer deserializer = new OpenSSHDeserializer(publicKeyBytes);
        deserializer.skip4Bytes();
        return OpenSSHKeyFactory.generatePublic(deserializer.getRest());
    }

    public void getPrivateKeys(String passphrase) throws DeserializationException {
        /*
         * TODO: Proper reading of private keys
         */
        OpenSSHDeserializer encryptedBytesDecoder = new OpenSSHDeserializer(encrypted.getValue());
        OpenSSHUInt32 checkInt1 = encryptedBytesDecoder.readUInt32();

        byte[] rest = decrypt(encryptedBytesDecoder.getRest(), passphrase);
        encryptedBytesDecoder = new OpenSSHDeserializer(decrypt(rest, passphrase));

        OpenSSHUInt32 checkInt2 = encryptedBytesDecoder.readUInt32();
        if ( ! checkInt1.getValue().equals(checkInt2.getValue())) {
            throw new IllegalArgumentException("Not valid main.openssh private key");
        }

        encryptedBytesDecoder.skip4Bytes();
        for (String key : keyTypes) {
            byte[] keyBytes = key.getBytes();
            if (Arrays.equals(keyBytes, encryptedBytesDecoder.probeBytes(keyBytes.length))) {
                encryptedBytesDecoder.readBytes(key.length());
            }
        }

        OpenSSHMPInt n = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt e = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt d = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt iqmp = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt p = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt q = encryptedBytesDecoder.readMPInt();
        OpenSSHString comment = encryptedBytesDecoder.readString();

        System.out.println(Arrays.toString(encryptedBytesDecoder.probeBytes(encryptedBytesDecoder.getRest().length)));
    }

    byte[] decrypt(byte[] content, String passphrase) {
        if (Arrays.equals(kdfname.getValue(), "bcrypt".getBytes(StandardCharsets.UTF_8))) {
            /*
             * TODO: add support for bcrypt
             */
        }
        else if (Arrays.equals(kdfname.getValue(), "none".getBytes(StandardCharsets.UTF_8))) {
            return content;
        }
        return null;
    }

    public OpenSSHString getCiphername() {
        return ciphername;
    }

    public OpenSSHString getKdfname() {
        return kdfname;
    }

    public OpenSSHString getKdfoptions() {
        return kdfoptions;
    }

    public LinkedList<OpenSSHPublicKey> getPublicKeys() {
        return publicKeys;
    }

    public OpenSSHString getEncrypted() {
        return encrypted;
    }
}