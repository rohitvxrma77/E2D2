package crypto;

import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;

public class EphemeralKeyPair {
    private final KeyPair x25519;
    private final KeyPair ed25519;

    private EphemeralKeyPair(KeyPair x, KeyPair e) {
        this.x25519 = x; this.ed25519 = e;
    }

    public static EphemeralKeyPair generate() {
        try {
            KeyPairGenerator kpgX = KeyPairGenerator.getInstance("XDH");
            kpgX.initialize(new NamedParameterSpec("X25519"));
            KeyPairGenerator kpgE = KeyPairGenerator.getInstance("Ed25519");
            return new EphemeralKeyPair(kpgX.generateKeyPair(), kpgE.generateKeyPair());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public PublicKey getXPublic() { return x25519.getPublic(); }
    public PrivateKey getXPrivate() { return x25519.getPrivate(); }
    public PublicKey getEdPublic() { return ed25519.getPublic(); }
    public PrivateKey getEdPrivate() { return ed25519.getPrivate(); }

    public byte[] getPublicKeyEncoded() {
        return Base64.getEncoder().encode(getEdPublic().getEncoded());
    }
}
