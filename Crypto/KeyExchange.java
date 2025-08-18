package crypto;

import javax.crypto.KeyAgreement;
import java.security.*;

public class KeyExchange {
    public static byte[] dh(PrivateKey myPriv, PublicKey theirPub) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(myPriv);
            ka.doPhase(theirPub, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
