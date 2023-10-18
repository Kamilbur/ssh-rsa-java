import openssh.DeserializationException;
import openssh.OpenSSHPrivateKeyV1;
import openssh.OpenSSHRSACertificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

class Main {
    public static void main(String[] args) throws DeserializationException, IOException {
        String certText = Files.readString(Paths.get("mk-key-cert.pub")).trim();
//        OpenSSHRSACertificate certificatex = new OpenSSHRSACertificate("2419214 1237409172094712309487123947");
        OpenSSHRSACertificate certificate = new OpenSSHRSACertificate(certText);
        System.out.println(certificate.getValidPrincipals());
        System.out.println(certificate.isValidTime());

        String keyText = Files.readString(Paths.get("mk-key")).trim();
        OpenSSHPrivateKeyV1 key = new OpenSSHPrivateKeyV1(keyText);
        System.out.println(certificate.isValidPrivateKey(key));

        String certText1 = Files.readString(Paths.get("user-key-cert.pub")).trim();
        OpenSSHRSACertificate certificate1 = new OpenSSHRSACertificate(certText1);
        System.out.println(certificate1.getValidPrincipals());
        System.out.println(certificate1.isValidTime());

        String keyText1 = Files.readString(Paths.get("user-key")).trim();
        OpenSSHPrivateKeyV1 key1 = new OpenSSHPrivateKeyV1(keyText1);
        System.out.println(certificate1.isValidPrivateKey(key1));
        System.out.println(certificate1.isValidPrivateKey(key));
    }
}
