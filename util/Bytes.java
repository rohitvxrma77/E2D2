package util;

import java.security.SecureRandom;

public class Bytes {
    private static final SecureRandom rnd = new SecureRandom();

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        rnd.nextBytes(b);
        return b;
    }
}
