package crypto.util;

import java.math.BigInteger;

/**
 * Utility class for serializing/deserializing BigInteger keys.
 */
public final class KeyUtils {

    private KeyUtils() {}

    /** Encode a BigInteger to byte array with 4-byte length prefix. */
    public static byte[] encodeBigInteger(BigInteger val) {
        byte[] bytes = val.toByteArray();
        byte[] result = new byte[4 + bytes.length];
        result[0] = (byte) (bytes.length >> 24);
        result[1] = (byte) (bytes.length >> 16);
        result[2] = (byte) (bytes.length >> 8);
        result[3] = (byte) (bytes.length);
        System.arraycopy(bytes, 0, result, 4, bytes.length);
        return result;
    }

    /** Decode a BigInteger from a byte array with 4-byte length prefix. */
    public static BigInteger decodeBigInteger(byte[] data, int offset) {
        int len = ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
        byte[] bytes = new byte[len];
        System.arraycopy(data, offset + 4, bytes, 0, len);
        return new BigInteger(bytes);
    }

    /** Get the total length of an encoded BigInteger (value bytes + 4-byte header). */
    public static int encodedLength(byte[] data, int offset) {
        int len = ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
        return 4 + len;
    }

    /** Concatenate multiple byte arrays. */
    public static byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) totalLen += arr.length;
        byte[] result = new byte[totalLen];
        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, pos, arr.length);
            pos += arr.length;
        }
        return result;
    }
}
