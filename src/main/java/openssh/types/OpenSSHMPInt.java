package openssh.types;

import java.math.BigInteger;

public class OpenSSHMPInt {
    private final BigInteger value;

    public OpenSSHMPInt(byte[] value) {
        this.value = new BigInteger(value);
    }

    public BigInteger getValue() {
        return value;
    }
}
