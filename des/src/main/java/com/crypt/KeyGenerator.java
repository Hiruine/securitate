package com.crypt;

import java.nio.charset.StandardCharsets;

import static com.crypt.Util.PERMUTED_CHOICE2;

public class KeyGenerator {

    private String originalKey;

    public KeyGenerator(String password) {
        this.originalKey = password;
    }


    public long[] generateKeys() {
        long key = Util.getLongFromBytes(originalKey.getBytes(StandardCharsets.UTF_8), 0);
        return createSubKeys(key);
    }

    /**
     * Generate 16 48-bit subkeys based on the provided 64-bit key
     * value.
     */
    private long[] createSubKeys(/* 64 bits */ long key) {
        long subKeys[] = new long[16];

        // perform the PC1 permutation
        key = Util.PC1(key);

        // split into 28-bit left and right (c and d) pairs.
        int c = (int) (key >> 28);
        int d = (int) (key & 0x0FFFFFFF);

        // for each of the 16 needed subkeys, perform a bit
        // rotation on each 28-bit keystuff half, then join
        // the halves together and permute to generate the subkey.
        for (int i = 0; i < 16; i++) {
            // rotate the 28-bit values
            if (Util.rotations[i] == 1) {
                // rotate by 1 bit
                c = ((c << 1) & 0x0FFFFFFF) | (c >> 27);
                d = ((d << 1) & 0x0FFFFFFF) | (d >> 27);
            } else {
                // rotate by 2 bits
                c = ((c << 2) & 0x0FFFFFFF) | (c >> 26);
                d = ((d << 2) & 0x0FFFFFFF) | (d >> 26);
            }

            // join the two keystuff halves together.
            long cd = (c & 0xFFFFFFFFL) << 28 | (d & 0xFFFFFFFFL);

            // perform the PC2 permutation
            subKeys[i] = Util.PC2(cd);
        }

        return subKeys; /* 48-bit values */
    }
}
