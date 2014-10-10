/*
 * Copyright (c) 2009, RSA, The Security Division of EMC.
 *
 * This file is used to demonstrate how to interface to an RSA
 * Security licensed development product.  You have a
 * royalty-free right to use, modify, reproduce and distribute this
 * demonstration file (including any modified version), provided that
 * you agree that RSA Security has no warranty, implied or
 * otherwise, or liability for this demonstration file or any modified
 * version.
 *
 * This file is based upon the RSA BSAFE Share for Java Platform sample
 * code util/Print.java.
 */


/**
 * This class contains methods which allow byte arrays to be printed to
 * System.out.
 */
public final class PrintBuffer {
    private PrintBuffer() {
        // Prevent instantiation.
    }


    /**
     * Given a <code>byte</code> array, print out the hex-encoding of that data,
     * in a visually pleasing format.
     *
     * @param byteArray The <code>byte</code> array to be printed.
     */
    public static void printBuffer(byte[] byteArray) {
        printBuffer(byteArray, 0, byteArray.length);
    }

    /**
     * Given a <code>byte</code> array, print the first length bytes of
     * that <code>byte</code> array.
     *
     * @param byteArray The <code>byte</code> array containing the data to be printed.
     * @param length    The amount of data to be printed.
     */
    public static void printBuffer(byte[] byteArray, int length) {
        printBuffer(byteArray, 0, length);
    }

    /**
     * Given some part of a <code>byte</code> array, print the
     * hex-encoding of that data in a visually pleasing format.
     *
     * @param byteArray The <code>byte</code> array containing data to print.
     * @param offset    The starting location of the data to print.
     * @param length    The amount of data to print.
     */
    public static void printBuffer(byte[] byteArray, int offset, int length) {
        StringBuffer textLine = new StringBuffer("                ");
        System.out.print("  0000: ");
        for (int i = 0; i < length; i++) {
            if (i % 16 == 0 && i != 0) {
                System.out.println("[" + textLine + "]");
                System.out.print("  " + hexString(i, 4) + ": ");
                for (int j = 0; j < 16; j++) {
                    textLine.setCharAt(j, ' ');
                }
            }
            System.out.print(hexString((int) byteArray[i + offset], 2) + " ");
            if (byteArray[i + offset] < 32 || byteArray[i + offset] > 127 ||
                    byteArray[i + offset] == 0x7f) {
                textLine.setCharAt(i % 16, '.');
            } else {
                textLine.setCharAt(i % 16, (char) byteArray[i + offset]);
            }
        }
        if (length % 16 != 0 || length == 0) {
            for (int i = 0; i < 16 - length % 16; i++) {
                System.out.print("   ");
            }
        }
        System.out.println("[" + textLine + "]");
    }

    private static String hexString(int value, int padding) {
        String hexString = "0123456789ABCDEF";
        StringBuffer tempString = new StringBuffer
                ("                                                                              ".substring(0, padding));
        int offset = padding - 1;

        for (int i = 0; i < padding; i++) {
            tempString.setCharAt(offset - i,
                    hexString.charAt(value >> i * 4 & 0xF));
        }
        return tempString.toString();
    }

}
