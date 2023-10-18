package openssh;

import openssh.types.*;

import java.util.Arrays;

class OpenSSHDeserializer {
    private int pointer;
    private final byte[] body;

    private static final int UINT32_SIZE = 4;
    private static final int UINT64_SIZE = 8;

    OpenSSHDeserializer(byte[] body) {
        pointer = 0;
        this.body = body;
    }

    public OpenSSHUInt32 readUInt32() throws IndexOutOfBoundsException {
        return new OpenSSHUInt32(readBytes(UINT32_SIZE));
    }

    public OpenSSHUInt64 readUInt64() throws IndexOutOfBoundsException {
        return new OpenSSHUInt64(readBytes(UINT64_SIZE));
    }

    public OpenSSHString readString() throws IndexOutOfBoundsException {
        int length = readUInt32().getValue().intValue();
        return new OpenSSHString(readBytes(length));
    }

    public OpenSSHMPInt readMPInt() throws IndexOutOfBoundsException {
        return new OpenSSHMPInt(readString().getValue());
    }

    public byte[] readBytes(int numberOfBytes) throws IndexOutOfBoundsException {
        byte[] val = probeBytes(numberOfBytes);
        pointer += numberOfBytes;
        return val;
    }

    public byte[] probeBytes(int numberOfBytes) throws IndexOutOfBoundsException {
        int endPointer = pointer + numberOfBytes;
        if (endPointer > body.length) {
            throw new IndexOutOfBoundsException("Index out of bound when reading bytes.");
        }
        return Arrays.copyOfRange(body, pointer, endPointer);
    }

    public byte[] probeBytesSafe(int numberOfBytes) {
        int endPointer = pointer + numberOfBytes;
        endPointer = Math.min(endPointer, body.length);
        return Arrays.copyOfRange(body, pointer, endPointer);
    }

    /* TODO: why sometimes there is a need to skip these 4 bytes?
     * Can't find it in specification.
     */
    public void skip4Bytes() throws IndexOutOfBoundsException {
        readBytes(4);
    }

    public byte[] getRest() {
        return Arrays.copyOfRange(body, pointer, body.length);
    }

    public boolean isEmpty() {
        return pointer >= body.length;
    }
}