package crypto.he;

import crypto.util.KeyUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Textbook RSA with multiplicative homomorphism.
 *
 * Homomorphic property: E(m1) * E(m2) mod N = E(m1 * m2 mod N)
 *
 * NOTE: Uses raw/textbook RSA (no padding) to preserve homomorphism.
 * This means it is NOT semantically secure — same plaintext → same ciphertext.
 * Only use for demonstrating multiplicative homomorphic properties.
 */
public class RSAHomomorphic implements HEInterface {

    private BigInteger p, q;      // prime factors
    private BigInteger n;          // modulus N = p * q
    private BigInteger phi;        // φ(N) = (p-1)(q-1)
    private BigInteger e;          // public exponent
    private BigInteger d;          // private exponent

    private static final BigInteger DEFAULT_E = BigInteger.valueOf(65537);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void generateKeyPair(int keySize) {
        int primeSize = keySize / 2;
        p = BigInteger.probablePrime(primeSize, RANDOM);
        q = BigInteger.probablePrime(primeSize, RANDOM);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Ensure gcd(e, phi) == 1
        e = DEFAULT_E;
        while (!e.gcd(phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.valueOf(2));
        }
        d = e.modInverse(phi);
    }

    @Override
    public BigInteger encrypt(BigInteger plaintext) {
        if (plaintext.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Plaintext must be < N");
        }
        return plaintext.modPow(e, n);
    }

    @Override
    public BigInteger decrypt(BigInteger ciphertext) {
        return ciphertext.modPow(d, n);
    }

    /**
     * Homomorphic multiplication: multiply two ciphertexts to get E(m1 * m2).
     */
    public BigInteger homomorphicMultiply(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(n);
    }

    @Override
    public byte[] getPublicKeyEncoded() {
        return KeyUtils.concat(
            KeyUtils.encodeBigInteger(e),
            KeyUtils.encodeBigInteger(n)
        );
    }

    /** Decode a public key from bytes. */
    public void loadPublicKey(byte[] encoded) {
        int offset = 0;
        e = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        n = KeyUtils.decodeBigInteger(encoded, offset);
    }

    @Override
    public byte[] getPrivateKeyEncoded() {
        return KeyUtils.concat(
            KeyUtils.encodeBigInteger(d),
            KeyUtils.encodeBigInteger(n),
            KeyUtils.encodeBigInteger(phi)
        );
    }

    /** Decode a private key from bytes. */
    public void loadPrivateKey(byte[] encoded) {
        int offset = 0;
        d = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        n = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        phi = KeyUtils.decodeBigInteger(encoded, offset);
    }

    @Override
    public String getAlgorithmName() {
        return "RSA-乘法同态";
    }

    @Override
    public BigInteger getOperationModulus() {
        return n;
    }

    public BigInteger getPublicExponent() { return e; }
    public BigInteger getModulus() { return n; }
}
