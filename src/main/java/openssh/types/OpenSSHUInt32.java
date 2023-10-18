package openssh.types;

import java.math.BigInteger;

public class OpenSSHUInt32 {
    private final BigInteger value;

    public OpenSSHUInt32(byte[] value) {
        this.value = new BigInteger(value);
    }

    public BigInteger getValue() {
        return value;
    }
}
