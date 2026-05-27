import crypto.he.Paillier;
import crypto.he.RSAHomomorphic;
import scenario.PrivacyDemo;

import java.math.BigInteger;

/**
 * Homomorphic Encryption — main entry.
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  基于同态加密的隐私数据保护系统实现                          ║");
        System.out.println("║  北京邮电大学 信息安全编程技术与实例开发 课程设计            ║");
        System.out.println("║  RSA 乘法同态 & Paillier 加法同态 方案对比                   ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // ---- Correctness verification ----
        runRSAVerification();
        System.out.println();
        runPaillierVerification();
        System.out.println();

        // ---- Privacy application demos ----
        PrivacyDemo demo = new PrivacyDemo();
        demo.runFullDemo();

        // ---- Performance comparison ----
        System.out.println("\n");
        runPerformanceComparison();

        System.out.println("\n所有测试完成。");
        System.out.println("\n按任意键退出...");
        try { System.in.read(); } catch (Exception ignored) {}
    }

    // ──────────────────────────────────────────────
    // RSA Homomorphic Correctness Verification
    // ──────────────────────────────────────────────

    private static void runRSAVerification() {
        System.out.println(repeat("=", 65));
        System.out.println("  RSA 乘法同态 — 正确性验证");
        System.out.println(repeat("=", 65));

        System.out.println("\n[1] 密钥生成 (2048-bit)...");
        RSAHomomorphic rsa = new RSAHomomorphic();
        rsa.generateKeyPair(2048);
        System.out.println("    密钥生成完成\n");

        // Test 1: Basic encrypt/decrypt
        System.out.println("[2] 基础加解密测试:");
        BigInteger m = new BigInteger("12345678901234567890");
        BigInteger c = rsa.encrypt(m);
        BigInteger mDec = rsa.decrypt(c);
        System.out.println("    明文: " + m);
        System.out.println("    密文: " + c.toString(16).substring(0, 40) + "...");
        System.out.println("    解密: " + mDec);
        System.out.println("    结果: " + (m.equals(mDec) ? "通过 ✓" : "失败 ✗"));

        // Test 2: Homomorphic multiplication
        System.out.println("\n[3] 同态乘法测试: E(m1) * E(m2) mod N = E(m1 * m2 mod N)");
        BigInteger m1 = new BigInteger("777");
        BigInteger m2 = new BigInteger("999");
        BigInteger c1 = rsa.encrypt(m1);
        BigInteger c2 = rsa.encrypt(m2);
        BigInteger cProduct = rsa.homomorphicMultiply(c1, c2);
        BigInteger decProduct = rsa.decrypt(cProduct);
        BigInteger expectedProduct = m1.multiply(m2).mod(rsa.getModulus());
        System.out.println("    m1 = " + m1 + ", m2 = " + m2);
        System.out.println("    D(E(m1) * E(m2) mod N) = " + decProduct);
        System.out.println("    m1 * m2 mod N          = " + expectedProduct);
        System.out.println("    结果: " + (decProduct.equals(expectedProduct) ? "通过 ✓" : "失败 ✗"));

        // Test 3: Multiplicative chain
        System.out.println("\n[4] 同态乘法链测试: E(2) * E(3) * E(5) * E(7) = E(210)");
        BigInteger[] nums = {BigInteger.valueOf(2), BigInteger.valueOf(3),
                             BigInteger.valueOf(5), BigInteger.valueOf(7)};
        BigInteger chainProduct = BigInteger.ONE;
        for (BigInteger num : nums) {
            chainProduct = rsa.homomorphicMultiply(chainProduct, rsa.encrypt(num));
        }
        BigInteger decChain = rsa.decrypt(chainProduct);
        System.out.println("    D(E(2)*E(3)*E(5)*E(7)) = " + decChain);
        System.out.println("    预期: 210");
        System.out.println("    结果: " + (decChain.longValue() == 210 ? "通过 ✓" : "失败 ✗"));
    }

    // ──────────────────────────────────────────────
    // Paillier Homomorphic Correctness Verification
    // ──────────────────────────────────────────────

    private static void runPaillierVerification() {
        System.out.println(repeat("=", 65));
        System.out.println("  Paillier 加法同态 — 正确性验证");
        System.out.println(repeat("=", 65));

        System.out.println("\n[1] 密钥生成 (1024-bit)...");
        Paillier paillier = new Paillier();
        paillier.generateKeyPair(1024);
        System.out.println("    密钥生成完成\n");

        // Test 1: Basic encrypt/decrypt
        System.out.println("[2] 基础加解密测试:");
        BigInteger m = new BigInteger("100");
        BigInteger c = paillier.encrypt(m);
        BigInteger dec = paillier.decrypt(c);
        System.out.println("    明文: " + m);
        System.out.println("    密文(hex): " + c.toString(16).substring(0, 40) + "...");
        System.out.println("    解密: " + dec);
        System.out.println("    结果: " + (m.equals(dec) ? "通过 ✓" : "失败 ✗"));

        // Test 2: Homomorphic addition
        System.out.println("\n[3] 同态加法测试: E(m1) * E(m2) mod N² = E(m1 + m2 mod N)");
        BigInteger m1 = BigInteger.valueOf(50);
        BigInteger m2 = BigInteger.valueOf(30);
        BigInteger c1 = paillier.encrypt(m1);
        BigInteger c2 = paillier.encrypt(m2);
        BigInteger cSum = paillier.homomorphicAdd(c1, c2);
        BigInteger decSum = paillier.decrypt(cSum);
        System.out.println("    m1 = " + m1 + ", m2 = " + m2);
        System.out.println("    D(E(m1) * E(m2)) = " + decSum);
        System.out.println("    m1 + m2          = " + (m1.longValue() + m2.longValue()));
        System.out.println("    结果: " + (decSum.longValue() == 80 ? "通过 ✓" : "失败 ✗"));

        // Test 3: Scalar multiplication
        System.out.println("\n[4] 标量乘法测试: E(m)^k = E(k * m mod N)");
        BigInteger msg = BigInteger.valueOf(25);
        BigInteger scalar = BigInteger.valueOf(4);
        BigInteger cMsg = paillier.encrypt(msg);
        BigInteger cScaled = paillier.homomorphicScalarMul(cMsg, scalar);
        BigInteger decScaled = paillier.decrypt(cScaled);
        System.out.println("    m = " + msg + ", k = " + scalar);
        System.out.println("    D(E(m)^k) = " + decScaled);
        System.out.println("    k * m     = " + msg.multiply(scalar));
        System.out.println("    结果: " + (decScaled.longValue() == 100 ? "通过 ✓" : "失败 ✗"));

        // Test 4: Semantic security — same plaintext → different ciphertexts
        System.out.println("\n[5] 语义安全验证 (相同明文 → 不同密文):");
        BigInteger pt = BigInteger.ONE;
        BigInteger ct1 = paillier.encrypt(pt);
        BigInteger ct2 = paillier.encrypt(pt);
        System.out.println("    E(1) 第一次: " + ct1.toString(16).substring(0, 40) + "...");
        System.out.println("    E(1) 第二次: " + ct2.toString(16).substring(0, 40) + "...");
        System.out.println("    两次密文相同? " + ct1.equals(ct2));
        System.out.println("    语义安全: " + (!ct1.equals(ct2) ? "通过 ✓ (Paillier 语义安全)" : "失败 ✗"));

        // Test 5: Chain addition
        System.out.println("\n[6] 同态加法链测试: Sum of 1...10 = 55");
        BigInteger chainSum = BigInteger.ONE;
        for (int i = 1; i <= 10; i++) {
            chainSum = paillier.homomorphicAdd(chainSum, paillier.encrypt(BigInteger.valueOf(i)));
        }
        BigInteger decChain = paillier.decrypt(chainSum);
        System.out.println("    D(Σ E(i)) = " + decChain + " (预期: 55)");
        System.out.println("    结果: " + (decChain.longValue() == 55 ? "通过 ✓" : "失败 ✗"));
    }

    // ──────────────────────────────────────────────
    // Performance Comparison
    // ──────────────────────────────────────────────

    private static void runPerformanceComparison() {
        System.out.println(repeat("=", 65));
        System.out.println("  性能对比: RSA 乘法同态 vs Paillier 加法同态");
        System.out.println(repeat("=", 65));

        int warmup = 5, iterations = 20;

        // --- RSA ---
        System.out.println("\n[RSA-2048] 密钥生成...");
        long t = System.nanoTime();
        RSAHomomorphic rsa = new RSAHomomorphic();
        rsa.generateKeyPair(2048);
        long tRsaKey = System.nanoTime() - t;
        System.out.printf("  密钥生成: %.2f ms%n", tRsaKey / 1_000_000.0);

        BigInteger rsaPt = BigInteger.valueOf(123456789012345L);
        for (int i = 0; i < warmup; i++) {
            BigInteger cc = rsa.encrypt(rsaPt);
            rsa.decrypt(cc);
        }
        double rsaEnc = 0, rsaDec = 0;
        for (int i = 0; i < iterations; i++) {
            long t0 = System.nanoTime();
            rsa.encrypt(rsaPt);
            long t1 = System.nanoTime();
            rsaEnc += (t1 - t0);

            BigInteger cc = rsa.encrypt(rsaPt);
            t0 = System.nanoTime();
            rsa.decrypt(cc);
            t1 = System.nanoTime();
            rsaDec += (t1 - t0);
        }
        System.out.printf("  加密 (avg): %.2f ms%n", rsaEnc / iterations / 1_000_000);
        System.out.printf("  解密 (avg): %.2f ms%n", rsaDec / iterations / 1_000_000);

        // --- Paillier ---
        System.out.println("\n[Paillier-1024] 密钥生成...");
        t = System.nanoTime();
        Paillier pai = new Paillier();
        pai.generateKeyPair(1024);
        long tPaiKey = System.nanoTime() - t;
        System.out.printf("  密钥生成: %.2f ms%n", tPaiKey / 1_000_000.0);

        BigInteger paiPt = BigInteger.valueOf(100);
        for (int i = 0; i < warmup; i++) {
            BigInteger cc = pai.encrypt(paiPt);
            pai.decrypt(cc);
        }
        double paiEnc = 0, paiDec = 0;
        for (int i = 0; i < iterations; i++) {
            long t0 = System.nanoTime();
            pai.encrypt(paiPt);
            long t1 = System.nanoTime();
            paiEnc += (t1 - t0);

            BigInteger cc = pai.encrypt(paiPt);
            t0 = System.nanoTime();
            pai.decrypt(cc);
            t1 = System.nanoTime();
            paiDec += (t1 - t0);
        }
        System.out.printf("  加密 (avg): %.2f ms%n", paiEnc / iterations / 1_000_000);
        System.out.printf("  解密 (avg): %.2f ms%n", paiDec / iterations / 1_000_000);

        // Summary
        System.out.println("\n" + repeat("=", 65));
        System.out.println("  性能汇总 (avg of " + iterations + " iterations)");
        System.out.println(repeat("=", 65));
        System.out.printf("  %-20s %10s %10s %10s%n", "方案", "密钥生成(ms)", "加密(ms)", "解密(ms)");
        System.out.println("  " + repeat("-", 50));
        System.out.printf("  %-20s %10.2f %10.2f %10.2f%n", "RSA-2048",
            tRsaKey / 1_000_000.0, rsaEnc / iterations / 1_000_000, rsaDec / iterations / 1_000_000);
        System.out.printf("  %-20s %10.2f %10.2f %10.2f%n", "Paillier-1024",
            tPaiKey / 1_000_000.0, paiEnc / iterations / 1_000_000, paiDec / iterations / 1_000_000);
        System.out.println();

        System.out.println(" 同态性质对比:");
        System.out.println("   RSA:      乘法同态 (E(m1)*E(m2)=E(m1*m2))，无加法同态");
        System.out.println("   Paillier: 加法同态 (E(m1)*E(m2)=E(m1+m2)) + 标量乘法");
        System.out.println("             语义安全 (相同明文产生不同密文)");
        System.out.println("   RSA 同态局限性: textbook RSA 无填充，不具语义安全性");
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
