# HE-System — 基于同态加密的隐私数据保护系统

北京邮电大学 信息安全编程技术与实例开发 课程设计 — 选题5

## 概述

基于**同态加密（Homomorphic Encryption）**技术实现隐私数据保护。包含两种方案：

| 方案 | 同态类型 | 安全性 | 说明 |
|------|----------|--------|------|
| RSA HE | 乘法同态 | 确定性加密 | Textbook RSA，E(m₁)·E(m₂) ≡ E(m₁·m₂) (mod N) |
| Paillier | 加法同态 | 语义安全 | E(m₁)·E(m₂) ≡ E(m₁+m₂) (mod N²)，支持标量乘法 |

## 同态性质

### RSA 乘法同态

- **加密**: c = mᵉ mod N
- **解密**: m = cᵈ mod N
- **同态乘法**: E(m₁) × E(m₂) mod N = E(m₁ × m₂ mod N)
- **局限**: 仅乘法同态，无随机填充 → 相同明文产生相同密文（不具语义安全性）

### Paillier 加法同态

- **加密**: c = gᵐ × rᴺ mod N²
- **解密**: m = L(cᴸ mod N²) × μ mod N
- **同态加法**: E(m₁) × E(m₂) mod N² = E(m₁ + m₂ mod N)
- **标量乘法**: E(m)ᵏ mod N² = E(k × m mod N)
- **语义安全**: 随机数 r 保证相同明文产生不同密文

## 应用场景

| 场景 | 技术 | 说明 |
|------|------|------|
| 隐私保护工资统计 | Paillier 加法同态 | HR 计算部门总工资，无法看到个体工资 |
| 隐私保护电子投票 | Paillier 加法同态 | 计票方只知总数，不知个体选择 |
| 隐私保护工资比较 | Paillier 加法同态 | 百万富翁问题 — 比较谁更高，不暴露具体数额 |
| RSA 乘法同态验证 | RSA 乘法同态 | 密文乘积 = 明文乘积的密文 |

## 项目结构

```
src/
├── Main.java                       # 入口 + 正确性验证 + 性能对比
├── crypto/
│   ├── he/
│   │   ├── HEInterface.java         # 同态加密公共接口
│   │   ├── RSAHomomorphic.java      # RSA 乘法同态实现
│   │   └── Paillier.java            # Paillier 加法同态实现
│   └── util/
│       └── KeyUtils.java            # 密钥序列化工具
└── scenario/
    └── PrivacyDemo.java             # 4 个应用场景演示
```

## 快速开始

**Windows** — 双击 `build.bat`  
**Linux/Mac** — `bash build.sh`

或手动编译运行：

```bash
javac -encoding UTF-8 -d out \
    src/crypto/util/KeyUtils.java \
    src/crypto/he/HEInterface.java \
    src/crypto/he/RSAHomomorphic.java \
    src/crypto/he/Paillier.java \
    src/scenario/PrivacyDemo.java \
    src/Main.java

java -Dfile.encoding=UTF-8 -cp out Main
```

## 环境要求

- JDK 1.8+
- 零外部依赖（仅 Java 标准库 `BigInteger` + `SecureRandom`）

## 验证结果

- RSA 基础加解密 ✓
- RSA 乘法同态: D(E(m₁) × E(m₂)) = m₁ × m₂ ✓
- Paillier 基础加解密 ✓
- Paillier 加法同态: D(E(m₁) × E(m₂)) = m₁ + m₂ ✓
- Paillier 标量乘法: D(E(m)ᵏ) = k × m ✓
- Paillier 语义安全: 相同明文 → 不同密文 ✓
- 工资统计场景: 总工资匹配，个体数据不可见 ✓
- 电子投票场景: 赞成票数匹配，个体投票不可见 ✓
- 工资比较场景: 正确判断大小关系，差值未公开 ✓

## 性能 (avg of 20 iterations)

| 操作 | RSA-2048 | Paillier-1024 |
|------|----------|---------------|
| 密钥生成 | ~120 ms | ~12 ms |
| 加密 | ~0.1 ms | ~5.0 ms |
| 解密 | ~10 ms | ~5.0 ms |
