package crypto.he;

import crypto.util.KeyUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Paillier cryptosystem with additive homomorphism.
 *
 * Properties:
 *   E(m1) * E(m2) mod N² = E(m1 + m2 mod N)
 *   E(m)^k mod N² = E(k * m mod N)
 *
 * Uses simplified variant with generator g = N + 1.
 * Semantically secure via random r in each encryption.
 */
public class Paillier implements HEInterface {

    private BigInteger p, q;
    private BigInteger n;          // modulus N = p * q
    private BigInteger nSquared;   // N²
    private BigInteger lambda;     // λ = lcm(p-1, q-1)
    private BigInteger mu;         // μ = L(g^λ mod N²)^(-1) mod N
    private BigInteger g;          // generator = N + 1

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void generateKeyPair(int keySize) {
        int primeSize = keySize / 2;
        p = BigInteger.probablePrime(primeSize, RANDOM);
        // Ensure p != q
        do {
            q = BigInteger.probablePrime(primeSize, RANDOM);
        } while (q.equals(p));

        n = p.multiply(q);
        nSquared = n.multiply(n);

        // λ = lcm(p-1, q-1)
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        lambda = lcm(pMinus1, qMinus1);

        // g = N + 1
        g = n.add(BigInteger.ONE);

        // μ = L(g^λ mod N²)^(-1) mod N
        // For g = N+1: g^λ ≡ 1 + λ*N (mod N²), so L(g^λ) = λ
        // Thus μ = λ^(-1) mod N
        mu = lambda.modInverse(n);
    }

    @Override
    public BigInteger encrypt(BigInteger plaintext) {
        if (plaintext.compareTo(n) >= 0 || plaintext.signum() < 0) {
            throw new IllegalArgumentException("Plaintext must be in [0, N)");
        }

        // c = g^m * r^N mod N²
        // Since g = N+1: g^m mod N² = (1+N)^m mod N² = 1 + m*N mod N²
        BigInteger gM = BigInteger.ONE.add(plaintext.multiply(n)).mod(nSquared);

        // Generate random r in Z_N^*
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), RANDOM);
        } while (r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1);

        BigInteger rN = r.modPow(n, nSquared);

        return gM.multiply(rN).mod(nSquared);
    }

    @Override
    public BigInteger decrypt(BigInteger ciphertext) {
        // c^λ mod N² → 1 + λ*m*N
        BigInteger cLambda = ciphertext.modPow(lambda, nSquared);
        // L(x) = (x - 1) / N
        BigInteger lValue = cLambda.subtract(BigInteger.ONE).divide(n);
        // m = L * μ mod N
        return lValue.multiply(mu).mod(n);
    }

    /**
     * Homomorphic addition: E(m1) * E(m2) mod N² = E(m1 + m2 mod N).
     */
    public BigInteger homomorphicAdd(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(nSquared);
    }

    /**
     * Scalar multiplication: E(m)^k mod N² = E(k * m mod N).
     */
    public BigInteger homomorphicScalarMul(BigInteger ciphertext, BigInteger scalar) {
        return ciphertext.modPow(scalar, nSquared);
    }

    /**
     * Scalar multiplication with long value.
     */
    public BigInteger homomorphicScalarMul(BigInteger ciphertext, long scalar) {
        return homomorphicScalarMul(ciphertext, BigInteger.valueOf(scalar));
    }

    @Override
    public byte[] getPublicKeyEncoded() {
        return KeyUtils.concat(
            KeyUtils.encodeBigInteger(n),
            KeyUtils.encodeBigInteger(g),
            KeyUtils.encodeBigInteger(nSquared)
        );
    }

    /** Decode a public key from bytes. */
    public void loadPublicKey(byte[] encoded) {
        int offset = 0;
        n = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        g = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        nSquared = KeyUtils.decodeBigInteger(encoded, offset);
    }

    @Override
    public byte[] getPrivateKeyEncoded() {
        return KeyUtils.concat(
            KeyUtils.encodeBigInteger(lambda),
            KeyUtils.encodeBigInteger(mu),
            KeyUtils.encodeBigInteger(n),
            KeyUtils.encodeBigInteger(nSquared)
        );
    }

    /** Decode a private key from bytes. */
    public void loadPrivateKey(byte[] encoded) {
        int offset = 0;
        lambda = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        mu = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        n = KeyUtils.decodeBigInteger(encoded, offset);
        offset += KeyUtils.encodedLength(encoded, offset);
        nSquared = KeyUtils.decodeBigInteger(encoded, offset);
    }

    @Override
    public String getAlgorithmName() {
        return "Paillier-加法同态";
    }

    @Override
    public BigInteger getOperationModulus() {
        return nSquared;
    }

    public BigInteger getModulus() { return n; }
    public BigInteger getModulusSquared() { return nSquared; }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.divide(a.gcd(b)).multiply(b);
    }
}
