package com.crypt;

public class Des {
    public static int feistel(int r, /* 48 bits */ long subKey) {
        // 1. expansion
        long e = Util.E(r);
        // 2. key mixing
        long x = e ^ subKey;
        // 3. substitution
        int dst = 0;
        for (int i = 0; i < 8; i++) {
            dst >>>= 4;
            int s = Util.S(8 - i, (byte) (x & 0x3F));
            dst |= s << 28;
            x >>= 6;
        }
        // 4. permutation
        return Util.P(dst);
    }
}
