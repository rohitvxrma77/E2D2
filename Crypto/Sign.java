package crypto;

import java.security.*;

public class Sign {
    public static byte[] sign(PrivateKey sk, byte[] msg) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(sk);
            s.update(msg);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(PublicKey pk, byte[] msg, byte[] sig) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(pk);
            s.update(msg);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }
}
