# HE-System — 基于同态加密的隐私数据保护系统

北京邮电大学 信息安全编程技术与实例开发 课程设计

## 概述

基于**同态加密（Homomorphic Encryption）**技术实现隐私数据保护。包含两种方案：

| 方案 | 同态类型 | 说明 |
|------|----------|------|
| RSA HE | 乘法同态 | Textbook RSA，E(m₁)·E(m₂) ≡ E(m₁·m₂) (mod N) |
| Paillier | 加法同态 | E(m₁)·E(m₂) ≡ E(m₁+m₂) (mod N²)，支持标量乘法，语义安全 |

## 同态性质

### RSA 乘法同态

- **加密**: c = m^e mod N
- **解密**: m = c^d mod N
- **同态乘法**: E(m₁) × E(m₂) mod N = E(m₁ × m₂ mod N)
- **局限**: 仅支持乘法同态，无填充（不具语义安全性）

### Paillier 加法同态

- **加密**: c = g^m × r^N mod N²
- **解密**: m = L(c^λ mod N²) × μ mod N
- **同态加法**: E(m₁) × E(m₂) mod N² = E(m₁ + m₂ mod N)
- **标量乘法**: E(m)^k mod N² = E(k × m mod N)
- **语义安全**: 随机数 r 保证相同明文产生不同密文

## 应用场景

1. **隐私保护工资统计** — Paillier 加法同态
2. **隐私保护电子投票** — Paillier 加法同态
3. **RSA 乘法同态验证** — 密文乘积

## 项目结构

```
src/
├── Main.java                     # 入口 + 正确性验证 + 性能对比
├── crypto/
│   ├── he/
│   │   ├── HEInterface.java       # 同态加密公共接口
│   │   ├── RSAHomomorphic.java    # RSA 乘法同态实现
│   │   └── Paillier.java          # Paillier 加法同态实现
│   └── util/
│       └── KeyUtils.java          # 密钥序列化工具
└── scenario/
    └── PrivacyDemo.java           # 应用场景演示
```

## 运行

**Windows** — 双击 `build.bat`  
**Linux/Mac** — `bash build.sh`

或手动：

```bash
javac -encoding UTF-8 -d out src/crypto/util/KeyUtils.java src/crypto/he/HEInterface.java src/crypto/he/RSAHomomorphic.java src/crypto/he/Paillier.java src/scenario/PrivacyDemo.java src/Main.java
java -Dfile.encoding=UTF-8 -cp out Main
```

## 环境要求

- JDK 1.8+
- 零外部依赖（仅使用 Java 标准库 BigInteger + SecureRandom）

## 验证结果

- RSA 乘法同态: D(E(m₁) × E(m₂)) == m₁ × m₂ ✓
- Paillier 加法同态: D(E(m₁) × E(m₂)) == m₁ + m₂ ✓
- Paillier 标量乘法: D(E(m)^k) == k × m ✓
- 语义安全: Paillier 相同明文 → 不同密文 ✓
- 工资统计场景 ✓
- 电子投票场景 ✓

## 性能 (avg, ~20 iterations)

| 操作 | RSA-2048 | Paillier-1024 |
|------|----------|---------------|
| 密钥生成 | 95.20 ms | 18.16 ms |
| 加密 | 0.09 ms | 4.94 ms |
| 解密 | 10.13 ms | 4.82 ms |
