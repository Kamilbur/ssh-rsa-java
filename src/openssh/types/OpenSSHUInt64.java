package openssh.types;

import java.math.BigInteger;

public class OpenSSHUInt64 {
    private final BigInteger value;

    public OpenSSHUInt64(byte[] value) {
        this.value = new BigInteger(value);
    }

    public BigInteger getValue() {
        return value;
    }
}
