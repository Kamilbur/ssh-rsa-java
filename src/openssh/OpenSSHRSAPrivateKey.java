package openssh;

import openssh.types.OpenSSHMPInt;
import openssh.types.OpenSSHString;
import openssh.types.OpenSSHUInt32;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedList;

public class OpenSSHRSAPrivateKey {
    private static final String MARK_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String MARK_END = "-----END OPENSSH PRIVATE KEY-----";
    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);

    /*
     * Specification is described in
     * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
     */
    private OpenSSHString ciphername;
    private OpenSSHString kdfname;
    private OpenSSHString kdfoptions;
    private LinkedList<OpenSSHString> publicKeys;
    private OpenSSHString encrypted;

    private final LinkedList<String> keyTypes = new LinkedList<>(Collections.singletonList(
            "ssh-rsa"
    ));

    public OpenSSHRSAPrivateKey(String key) {
        byte[] keyBytes = key.replace(MARK_BEGIN, "")
                .replace(MARK_END, "")
                .replace("\n", "")
                .getBytes(StandardCharsets.UTF_8);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] body = decoder.decode(keyBytes);
        decode(body);
    }

    void decode(byte[] body) {
        OpenSSHKeyBytesDecoder bytesDecoder = new OpenSSHKeyBytesDecoder(body);
        byte[] prefix = bytesDecoder.readBytes(AUTH_MAGIC.length);

        if ( ! Arrays.equals(prefix, AUTH_MAGIC)) {
            throw new IllegalArgumentException("Not valid openssh private key");
        }

        ciphername = bytesDecoder.readString();
        kdfname = bytesDecoder.readString();
        kdfoptions = bytesDecoder.readString();

        long numberOfPublicKeys = bytesDecoder.readUInt32().getValue().longValue();
        publicKeys = new LinkedList<>();
        for (long i = 0; i < numberOfPublicKeys; i++) {
            OpenSSHString publicKey = bytesDecoder.readString();
//            PublicKey
            publicKey.getValue();
            publicKeys.add(publicKey);
        }
        encrypted = bytesDecoder.readString();
    }

    public void getPrivateKeys(String passphrase) {
        OpenSSHKeyBytesDecoder encryptedBytesDecoder = new OpenSSHKeyBytesDecoder(encrypted.getValue());

        OpenSSHUInt32 checkInt1 = encryptedBytesDecoder.readUInt32();

        byte[] rest = encryptedBytesDecoder.getRest();
        encryptedBytesDecoder = new OpenSSHKeyBytesDecoder(decrypt(rest, passphrase));

        OpenSSHUInt32 checkInt2 = encryptedBytesDecoder.readUInt32();
        if ( ! checkInt1.getValue().equals(checkInt2.getValue())) {
            throw new IllegalArgumentException("Not valid openssh private key");
        }

        /* TODO: why omit these 4 bytes */
        encryptedBytesDecoder.readUInt32();
        System.out.println(Arrays.toString(encryptedBytesDecoder.probeBytes(7)));
        for (byte[] key : keyTypes) {
            if (Arrays.equals(key, encryptedBytesDecoder.probeBytes(key.length))) {
                encryptedBytesDecoder.readBytes(key.length);
            }
        }

        OpenSSHMPInt n = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt e = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt d = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt iqmp = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt p = encryptedBytesDecoder.readMPInt();
        OpenSSHMPInt q = encryptedBytesDecoder.readMPInt();
        OpenSSHString comment = encryptedBytesDecoder.readString();

//        try {
//            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n.getValue(), d.getValue());
//            KeyFactory factory = KeyFactory.getInstance("RSA");
//            PrivateKey key = factory.generatePrivate(spec);
//        }
//        catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
//            exception.printStackTrace();
//        }

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

    public LinkedList<OpenSSHString> getPublicKeys() {
        return publicKeys;
    }

    public OpenSSHString getEncrypted() {
        return encrypted;
    }
}