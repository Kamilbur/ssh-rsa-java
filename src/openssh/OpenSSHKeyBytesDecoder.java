package openssh;

import openssh.types.OpenSSHMPInt;
import openssh.types.OpenSSHString;
import openssh.types.OpenSSHUInt32;
import openssh.types.OpenSSHUInt64;

import java.util.Arrays;

class OpenSSHKeyBytesDecoder {
    private int pointer;
    private final byte[] body;

    private static final int UINT32_SIZE = 4;
    private static final int UINT64_SIZE = 8;

    OpenSSHKeyBytesDecoder(byte[] body) {
        pointer = 0;
        this.body = body;
    }

    public OpenSSHUInt32 readUInt32() {
        int endPointer = pointer + UINT32_SIZE;
        if (endPointer > body.length) {
            throw new IllegalArgumentException("Invalid body");
        }
        byte[] val = Arrays.copyOfRange(body, pointer, endPointer);
        pointer = endPointer;
        return new OpenSSHUInt32(val);
    }

    public OpenSSHUInt64 readUInt64() {
        int endPointer = pointer + UINT64_SIZE;
        if (endPointer > body.length) {
            throw new IllegalArgumentException("Invalid body");
        }
        byte[] val = Arrays.copyOfRange(body, pointer, endPointer);
        pointer = endPointer;
        return new OpenSSHUInt64(val);
    }

    public OpenSSHString readString() {
        int length = readUInt32().getValue().intValue();
        int endPointer = pointer + length;
        if (endPointer > body.length) {
            throw new IllegalArgumentException("Invalid body");
        }
        byte[] val = Arrays.copyOfRange(body, pointer, endPointer);
        pointer = endPointer;
        return new OpenSSHString(val);
    }

    public OpenSSHMPInt readMPInt() {
        byte[] value = readString().getValue();
        return new OpenSSHMPInt(value);
    }

    public byte[] readBytes(int numberOfBytes) {
        int endPointer = pointer + numberOfBytes;
        if (endPointer > body.length) {
            throw new IllegalArgumentException("Invalid body");
        }
        byte[] val = Arrays.copyOfRange(body, pointer, endPointer);
        pointer = endPointer;
        return val;
    }

    public byte[] probeBytes(int numberOfBytes) {
        int endPointer = pointer + numberOfBytes;
        if (endPointer > body.length) {
            throw new IllegalArgumentException("Invalid body");
        }
        return Arrays.copyOfRange(body, pointer, endPointer);
    }

    public byte[] getRest() {
        return Arrays.copyOfRange(body, pointer, body.length);
    }

    public boolean isEmpty() {
        return pointer >= body.length;
    }
}