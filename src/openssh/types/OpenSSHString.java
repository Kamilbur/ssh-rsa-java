package openssh.types;

import java.nio.charset.StandardCharsets;

public class OpenSSHString {
    private final byte[] value;

    public OpenSSHString(byte[] value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return new String(value, StandardCharsets.UTF_8);
    }

    public byte[] getValue() {
        return value;
    }
}
