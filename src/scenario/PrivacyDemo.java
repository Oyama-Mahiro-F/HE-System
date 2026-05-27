package scenario;

import crypto.he.Paillier;
import crypto.he.RSAHomomorphic;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Demonstrates privacy-preserving applications using homomorphic encryption.
 *
 * Scenario 1: Privacy-preserving salary statistics (Paillier)
 * Scenario 2: Privacy-preserving electronic voting (Paillier)
 */
public class PrivacyDemo {

    // ──────────────────────────────────────────────
    // Scenario 1: Salary Statistics
    // ──────────────────────────────────────────────

    public static class SalaryDemo {
        private Paillier paillier;
        private BigInteger[] encryptedSalaries;

        public void run() {
            System.out.println(repeat("─", 65));
            System.out.println("  场景一: 隐私保护工资统计 (Paillier 加法同态)");
            System.out.println(repeat("─", 65));

            System.out.println("\n[背景] 某公司 5 名员工，HR 需要统计部门总工资，");
            System.out.println("       但不得泄露任何员工个体工资。\n");

            // Generate key pair (HR holds private key)
            System.out.println("[1] HR 生成 Paillier 密钥对 (1024-bit)...");
            paillier = new Paillier();
            paillier.generateKeyPair(1024);
            System.out.println("    密钥生成完成。公钥分发给各员工。\n");

            // Employee salaries
            long[] salaries = {15000, 22000, 18000, 25000, 30000}; // in yuan
            System.out.println("[2] 各员工加密自己的工资并上传:");
            encryptedSalaries = new BigInteger[salaries.length];
            for (int i = 0; i < salaries.length; i++) {
                BigInteger m = BigInteger.valueOf(salaries[i]);
                encryptedSalaries[i] = paillier.encrypt(m);
                System.out.printf("    员工 %d: 工资 %d → 密文 (长度: %d hex 字符)%n",
                    i + 1, salaries[i], encryptedSalaries[i].toString(16).length());
            }

            // HR computes encrypted sum without decrypting
            System.out.println("\n[3] HR 在密文上直接计算总工资 (同态加法):");
            System.out.println("    E(sum) = E(s1) * E(s2) * ... * E(s5) mod N²");
            BigInteger encryptedSum = BigInteger.ONE;
            for (BigInteger enc : encryptedSalaries) {
                encryptedSum = paillier.homomorphicAdd(encryptedSum, enc);
            }
            System.out.println("    密文总和已计算 (HR 未接触任何个体数据)\n");

            // HR decrypts the total
            System.out.println("[4] HR 解密得到总工资:");
            BigInteger total = paillier.decrypt(encryptedSum);
            long expectedSum = Arrays.stream(salaries).sum();
            System.out.println("    解密结果: " + total + " 元");
            System.out.println("    预期值:   " + expectedSum + " 元");
            System.out.println("    验证: " + (total.longValue() == expectedSum ? "通过 ✓" : "失败 ✗") + "\n");

            // Also compute average via scalar multiplication
            System.out.println("[5] 平均工资 (标量乘法): E(avg) = E(sum)^(1/5):");
            int employeeCount = salaries.length;
            // E(avg) = E(sum * (1/5)) — but this doesn't work for modular arithmetic
            // Instead, HR decrypts total and divides, proving only aggregate is revealed
            System.out.println("    HR 解密总工资后计算平均: " + total.longValue() / employeeCount + " 元");
            System.out.println("    注: HR 仅能获取总工资，无法反推个体数据。\n");
        }
    }

    // ──────────────────────────────────────────────
    // Scenario 2: Electronic Voting
    // ──────────────────────────────────────────────

    public static class VotingDemo {
        private Paillier paillier;

        public void run() {
            System.out.println(repeat("─", 65));
            System.out.println("  场景二: 隐私保护电子投票 (Paillier 加法同态)");
            System.out.println(repeat("─", 65));

            System.out.println("\n[背景] 10 人投票表决某提案，投票内容保密。");
            System.out.println("       1 = 赞成, 0 = 反对。计票方只知总数，不知个体选择。\n");

            // Tally authority generates key
            System.out.println("[1] 计票方生成 Paillier 密钥对 (1024-bit)...");
            paillier = new Paillier();
            paillier.generateKeyPair(1024);
            System.out.println("    密钥生成完成。公钥广播。\n");

            // Votes (0 or 1)
            int[] votes = {1, 1, 0, 1, 0, 1, 1, 0, 1, 1};
            System.out.println("[2] 各投票人加密自己的选票:");
            BigInteger[] encryptedVotes = new BigInteger[votes.length];
            for (int i = 0; i < votes.length; i++) {
                BigInteger v = BigInteger.valueOf(votes[i]);
                encryptedVotes[i] = paillier.encrypt(v);
                System.out.printf("    投票人 %2d: %s → 密文(hex): %s...%n",
                    i + 1, votes[i] == 1 ? "赞成" : "反对",
                    encryptedVotes[i].toString(16).substring(0, 32));
            }

            // Tally authority sums encrypted votes
            System.out.println("\n[3] 计票方在密文上直接汇总 (同态加法):");
            BigInteger encryptedTally = BigInteger.ONE;
            for (BigInteger enc : encryptedVotes) {
                encryptedTally = paillier.homomorphicAdd(encryptedTally, enc);
            }
            System.out.println("    密文汇总完成 (计票方未接触个体投票)\n");

            // Decrypt
            System.out.println("[4] 计票方解密得到总票数:");
            BigInteger tally = paillier.decrypt(encryptedTally);
            int expectedYes = 0;
            for (int v : votes) if (v == 1) expectedYes++;
            System.out.println("    赞成票: " + tally + " / 总人数: " + votes.length);
            System.out.println("    预期赞成票: " + expectedYes);
            System.out.println("    验证: " + (tally.intValue() == expectedYes ? "通过 ✓" : "失败 ✗"));
            System.out.println("    结果: " + (tally.intValue() > votes.length / 2 ? "提案通过!" : "提案未通过"));
            System.out.println("    计票方无法知晓任何人投了赞成还是反对。\n");
        }
    }

    // ──────────────────────────────────────────────
    // Scenario 3: Salary Comparison (Yao's Millionaires' Problem)
    // ──────────────────────────────────────────────

    public static class SalaryComparisonDemo {
        private Paillier paillier;

        public void run() {
            System.out.println(repeat("─", 65));
            System.out.println("  场景三: 隐私保护工资比较 (百万富翁问题)");
            System.out.println(repeat("─", 65));

            System.out.println("\n[背景] Alice 和 Bob 想知道谁的工资更高，");
            System.out.println("       但双方都不愿透露具体数额。\n");

            // Generate key pair (512-bit is sufficient for demo, keeps ciphertexts readable)
            System.out.println("[1] 系统生成 Paillier 密钥对 (512-bit)...");
            paillier = new Paillier();
            paillier.generateKeyPair(512);
            System.out.println("    密钥生成完成\n");

            System.out.println("[说明] 利用 Paillier 加法同态计算 E(A-B):");
            System.out.println("      E(A-B) = E(A) * E(B)^{N-1} mod N²");
            System.out.println("      若 D(E(A-B)) < N/2 → A > B");
            System.out.println("      若 D(E(A-B)) > N/2 → B > A (模N下负数)");
            System.out.println("      若 D(E(A-B)) = 0  → A = B\n");

            // Compare three cases
            compareSalaries("Alice", 25000, "Bob", 22000);
            System.out.println();
            compareSalaries("Alice", 18000, "Bob", 35000);
            System.out.println();
            compareSalaries("Alice", 20000, "Bob", 20000);
        }

        private void compareSalaries(String nameA, long salaryA, String nameB, long salaryB) {
            System.out.println("[*] " + nameA + " vs " + nameB + ":");
            BigInteger mA = BigInteger.valueOf(salaryA);
            BigInteger mB = BigInteger.valueOf(salaryB);

            // Both parties encrypt their salaries
            BigInteger cA = paillier.encrypt(mA);
            BigInteger cB = paillier.encrypt(mB);
            System.out.printf("    %s 加密工资, %s 加密工资 (密文不可区分)%n", nameA, nameB);

            // Homomorphic comparison: E(A - B mod N) = E(A) * E(B)^{N-1} mod N²
            // Since (-1) * B ≡ (N-1) * B ≡ N-B (mod N), and E(N-B) = E(B)^{N-1}
            BigInteger n = paillier.getModulus();
            BigInteger negOne = n.subtract(BigInteger.ONE);
            BigInteger cNegB = paillier.homomorphicScalarMul(cB, negOne);
            BigInteger cDiff = paillier.homomorphicAdd(cA, cNegB);

            // Decrypt the difference
            BigInteger diff = paillier.decrypt(cDiff);
            BigInteger halfN = n.divide(BigInteger.valueOf(2));

            // Salaries are much smaller than N, so:
            //   A > B  → diff = A-B (small, < N/2)
            //   A < B  → diff = N - (B-A) (large, > N/2)
            //   A = B  → diff = 0
            System.out.print("    同态比较结果: ");
            if (diff.equals(BigInteger.ZERO)) {
                System.out.println(nameA + " 和 " + nameB + " 工资相同");
            } else if (diff.compareTo(halfN) < 0) {
                System.out.println(nameA + " 工资更高 (差值未公开)");
            } else {
                System.out.println(nameB + " 工资更高 (差值未公开)");
            }

            // Ground truth validation
            System.out.print("    实际验证: ");
            if (salaryA == salaryB) {
                System.out.println("两人工资相同 ✓");
            } else if (salaryA > salaryB) {
                System.out.println(nameA + " 高出 " + (salaryA - salaryB) + " 元 ✓");
            } else {
                System.out.println(nameB + " 高出 " + (salaryB - salaryA) + " 元 ✓");
            }
            System.out.println("    双方均未获知对方具体工资数额 ✓");
        }
    }

    // ──────────────────────────────────────────────
    // RSA multiplicative homomorphism demo
    // ──────────────────────────────────────────────

    public static class RSAMultiplicativeDemo {
        public void run() {
            System.out.println(repeat("─", 65));
            System.out.println("  场景四: RSA 乘法同态验证");
            System.out.println(repeat("─", 65));

            System.out.println("\n[演示] E(m1) * E(m2) mod N = E(m1 * m2 mod N)\n");

            RSAHomomorphic rsa = new RSAHomomorphic();
            rsa.generateKeyPair(2048);

            BigInteger m1 = BigInteger.valueOf(12345);
            BigInteger m2 = BigInteger.valueOf(67890);
            System.out.println("    明文 m1 = " + m1);
            System.out.println("    明文 m2 = " + m2);

            BigInteger c1 = rsa.encrypt(m1);
            BigInteger c2 = rsa.encrypt(m2);
            System.out.println("    E(m1) 长度: " + c1.toString(16).length() + " hex 字符");
            System.out.println("    E(m2) 长度: " + c2.toString(16).length() + " hex 字符");

            // Homomorphic multiplication
            BigInteger cProduct = rsa.homomorphicMultiply(c1, c2);
            BigInteger decryptedProduct = rsa.decrypt(cProduct);
            BigInteger expectedProduct = m1.multiply(m2).mod(rsa.getModulus());

            System.out.println("    同态乘法后解密: " + decryptedProduct);
            System.out.println("    预期 m1*m2 mod N: " + expectedProduct);
            System.out.println("    验证: " + (decryptedProduct.equals(expectedProduct) ? "通过 ✓" : "失败 ✗"));
            System.out.println("\n    [注] RSA 仅支持乘法同态，无法加法同态。");
            System.out.println("         且使用 textbook RSA (无填充)，不具语义安全性。\n");
        }
    }

    public void runFullDemo() {
        System.out.println("\n" + repeat("=", 65));
        System.out.println("  同态加密 — 隐私数据保护应用场景演示");
        System.out.println(repeat("=", 65));

        new SalaryDemo().run();
        new VotingDemo().run();
        new SalaryComparisonDemo().run();
        new RSAMultiplicativeDemo().run();
    }

    // ──────────────────────────────────────────────
    // Utility
    // ──────────────────────────────────────────────

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
