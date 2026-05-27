#!/bin/bash
SRC_DIR="src"
OUT_DIR="out"

mkdir -p "$OUT_DIR"

echo "================================================================"
echo "  Compiling HE System..."
echo "================================================================"
javac -encoding UTF-8 -d "$OUT_DIR" \
    "$SRC_DIR/crypto/util/KeyUtils.java" \
    "$SRC_DIR/crypto/he/HEInterface.java" \
    "$SRC_DIR/crypto/he/RSAHomomorphic.java" \
    "$SRC_DIR/crypto/he/Paillier.java" \
    "$SRC_DIR/scenario/PrivacyDemo.java" \
    "$SRC_DIR/Main.java"

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo ""
echo "================================================================"
echo "  Running HE System Demo..."
echo "================================================================"
echo ""
java -Dfile.encoding=UTF-8 -cp "$OUT_DIR" Main
