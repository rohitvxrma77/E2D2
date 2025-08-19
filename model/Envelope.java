package model;

public class Envelope {
    public final byte[] senderEd25519Der;
    public final byte[] senderX25519Der;
    public final byte[] salt;    // HKDF salt
    public final byte[] nonce;
    public final byte[] aad;     // optional
    public final byte[] ciphertext;
    public final byte[] signature;// Ed25519 over (senderXDer||salt||nonce||aad||ciphertext)

    public Envelope(byte[] id, byte[] x, byte[] salt, byte[] nonce, byte[] aad, byte[] ct, byte[] sig) {
        this.senderEd25519Der = id; this.senderX25519Der = x; this.salt = salt; this.nonce = nonce; this.aad = aad; this.ciphertext = ct; this.signature = sig;
    }
}
