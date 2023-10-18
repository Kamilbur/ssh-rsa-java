package openssh;

abstract public class OpenSSHCertificate extends OpenSSHKey {
    public abstract boolean isValidPrivateKey(OpenSSHPrivateKeyV1 privateKey);
}
