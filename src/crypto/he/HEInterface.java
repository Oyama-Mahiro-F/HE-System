package crypto.he;

import java.math.BigInteger;

/**
 * Common interface for homomorphic encryption schemes.
 */
public interface HEInterface {

    /** Generate a key pair. */
    void generateKeyPair(int keySize);

    /** Encrypt a plaintext BigInteger under a public key. */
    BigInteger encrypt(BigInteger plaintext);

    /** Decrypt a ciphertext BigInteger using the private key. */
    BigInteger decrypt(BigInteger ciphertext);

    /** Get the public key as encoded bytes. */
    byte[] getPublicKeyEncoded();

    /** Get the private key as encoded bytes. */
    byte[] getPrivateKeyEncoded();

    /** Get the algorithm name. */
    String getAlgorithmName();

    /** The modulus (or modulus squared) used for homomorphic operations. */
    BigInteger getOperationModulus();
}
