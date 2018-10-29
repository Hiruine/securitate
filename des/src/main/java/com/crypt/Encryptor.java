package com.crypt;

import java.nio.charset.StandardCharsets;

public class Encryptor {

    private final String inputMessage;
    private final KeyGenerator keyGenerator;


    public Encryptor(String inputMessage, KeyGenerator keyGenerator) {
        this.inputMessage = inputMessage;
        this.keyGenerator = keyGenerator;
    }

    public String encrypt() {
        long message = Util.getLongFromBytes(inputMessage.getBytes(StandardCharsets.UTF_8), 0);
        long subKeys[] = keyGenerator.generateKeys();

        byte[] encryptedMessage = Util.getBytesFromLong(0, encryptBlock(message, subKeys));

        return new String(encryptedMessage, StandardCharsets.UTF_8);
    }

    /**
     * Encrypt the supplied message with the provided key, and return
     * the ciphertext.  If the message is not a multiple of 64 bits
     * (8 bytes), then it is padded with zeros.
     * <p>
     * This method uses the Electronic Code Book (ECB) mode of
     * operation -- each 64-bit block is encrypted individually with
     * the same key.
     */
    private long encryptBlock(long message, long subKeys[]) {

        long initialPermutation = Util.IP(message);

        // split the 32-bit value into 16-bit left and right halves.
        int leftBlock = (int) (initialPermutation>>32);
        int rightBlock = (int) (initialPermutation&0xFFFFFFFFL);

        // perform 16 rounds
        for (int i=0; i<16; i++) {
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
