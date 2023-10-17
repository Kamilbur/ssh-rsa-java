import openssh.DeserializationException;
import openssh.OpenSSHPrivateKey;
import openssh.OpenSSHRSACertificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

class Main {
    public static void main(String[] args) throws IOException, DeserializationException {
        String certText = Files.readString(Paths.get("mk-key-cert.pub")).trim();
        OpenSSHRSACertificate certificate = new OpenSSHRSACertificate(certText);

        System.out.println(certificate.getValidPrincipals());
        System.out.println(certificate.isValid());

        String certText1 = Files.readString(Paths.get("user-key-cert.pub")).trim();
        OpenSSHRSACertificate certificate1 = new OpenSSHRSACertificate(certText1);

        System.out.println(certificate1.getValidPrincipals());
        System.out.println(certificate1.isValid());

        String keyText = Files.readString(Paths.get("mk-key")).trim();
        OpenSSHPrivateKey key = new OpenSSHPrivateKey(keyText);

//        System.out.println(key.getCiphername());
//        System.out.println(key.getKdfname());
//        System.out.println(key.getKdfoptions());
//        System.out.println(key.getPublicKeys());
//        System.out.println(key.getEncrypted());

        key.getPrivateKeys("");
    }
}
