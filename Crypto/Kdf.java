package crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Kdf {
    public static byte[] hkdf(byte[] ikm, byte[] salt, String info, int len) {
        try {
            // HKDF-Extract
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            // HKDF-Expand
            byte[] result = new byte[len];
            byte[] t = new byte[0];
            int pos = 0, ctr = 1;
            while (pos < len) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                mac.update(info.getBytes(StandardCharsets.UTF_8));
                mac.update((byte) ctr);
                t = mac.doFinal();
                int cpy = Math.min(t.length, len - pos);
                System.arraycopy(t, 0, result, pos, cpy);
                pos += cpy; ctr++;
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] zeros(int n) {
        return new byte[n];
    }

    public static byte[] first(byte[] b, int n) {
        return Arrays.copyOf(b, n);
    }
}
