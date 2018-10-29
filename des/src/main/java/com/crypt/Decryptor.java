package com.crypt;

import java.nio.charset.StandardCharsets;

public class Decryptor {

    private final String encryptedMessage;
    private final KeyGenerator keyGenerator;

    public Decryptor(String encryptedMessage, KeyGenerator keyGenerator) {
        this.encryptedMessage = encryptedMessage;
        this.keyGenerator = keyGenerator;
    }

    public String decrypt() {
        long message = Util.getLongFromBytes(encryptedMessage.getBytes(StandardCharsets.UTF_8), 0);
        long subKeys[] = keyGenerator.generateKeys();

        byte[] encryptedMessage = Util.getBytesFromLong(0, decryptBlock(message, subKeys));

        return new String(encryptedMessage, StandardCharsets.UTF_8);
    }

    private long decryptBlock(long message, long subKeys[]) {

        long initialPermutation = Util.IP(message);

        // split the 32-bit value into 16-bit left and right halves.
        int leftBlock = (int) (initialPermutation>>32);
        int rightBlock = (int) (initialPermutation&0xFFFFFFFFL);

        // perform 16 rounds
        for (int i = 15; i >= 0; i--) {
            int previous_l = leftBlock;
            // the right half becomes the new left half.
            leftBlock = rightBlock;
            // the Feistel function is applied to the old left half
            // and the resulting value is stored in the right half.
            rightBlock = previous_l ^ Des.feistel(rightBlock, subKeys[i]);
        }

        // reverse the two 32-bit segments (left to right; right to left)
        long rl = (rightBlock&0xFFFFFFFFL)<<32 | (leftBlock&0xFFFFFFFFL);

        // apply the final permutation
        long finalPermutation = Util.FP(rl);

        // return the ciphertext
        return finalPermutation;
    }
}
