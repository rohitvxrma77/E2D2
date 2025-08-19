package net;

import crypto.Aead;
import crypto.Kdf;
import crypto.KeyExchange;
import crypto.NonceSeq;
import crypto.Sign;
import model.Envelope;
import model.Message;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class SecureChannel {
    private final PublicKey myEdPub;
    private final PrivateKey myXPriv;
    private final PublicKey theirXPub;
    private final PublicKey theirEdPub;
    private final SecureRandom rnd = new SecureRandom();
    private final NonceSeq nonceSeq;

    public SecureChannel(PrivateKey myXPriv, PublicKey myEdPub, PublicKey theirXPub, PublicKey theirEdPub) {
        this.myXPriv = myXPriv;
        this.myEdPub = myEdPub;
        this.theirXPub = theirXPub;
        this.theirEdPub = theirEdPub;
        byte[] base = new byte[4];
        rnd.nextBytes(base);
        this.nonceSeq = new NonceSeq(base);
    }

    private byte[] deriveKey(byte[] salt, byte[] shared) {
        byte[] okm = Kdf.hkdf(shared, salt, "E2D2-AESGCM", 32);
        return Kdf.first(okm, 32);
    }

    public Envelope encrypt(Message msg, byte[] senderIdDer, byte[] senderXDer) {
        byte[] salt = new byte; rnd.nextBytes(salt);
        byte[] shared = KeyExchange.dh(myXPriv, theirXPub);
        byte[] k = deriveKey(salt, shared);
        byte[] nonce = nonceSeq.next();

        byte[] payload = encodeMessage(msg);
        byte[] aad = ByteBuffer.allocate(8).putLong(msg.getExpiresAtMs()).array();
        byte[] ct = Aead.seal(k, nonce, payload, aad);

        byte[] signed = concat(senderXDer, salt, nonce, aad, ct);
        byte[] sig = Sign.sign(cryptoKeyFinder.findEdPrivate(), signed); // see note below
        return new Envelope(senderIdDer, senderXDer, salt, nonce, aad, ct, sig);
    }

    public Message decrypt(Envelope env, PrivateKey myXPriv, PublicKey theirXPub, PublicKey theirEdPub) {
        if (!Sign.verify(theirEdPub, concat(env.senderX25519Der, env.salt, env.nonce, env.aad, env.ciphertext), env.signature))
            return null;
        byte[] shared = KeyExchange.dh(myXPriv, theirXPub);
        byte[] k = deriveKey(env.salt, shared);
        byte[] pt = Aead.open(k, env.nonce, env.ciphertext, env.aad);
        if (pt == null) return null;
        Message m = decodeMessage(pt);
        if (System.currentTimeMillis() > m.getExpiresAtMs()) return null;
        return m;
    }

    private static byte[] encodeMessage(Message m) {
        if (m.isText()) {
            byte[] tb = m.getText().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ByteBuffer b = ByteBuffer.allocate(1+4+tb.length+8);
            b.put((byte)1).putInt(tb.length).put(tb).putLong(m.getExpiresAtMs());
            return b.array();
        } else {
            byte[] db = m.getData();
            byte[] mime = m.getMime().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ByteBuffer b = ByteBuffer.allocate(1+2+mime.length+4+db.length+8);
            b.put((byte)2).putShort((short)mime.length).put(mime).putInt(db.length).put(db).putLong(m.getExpiresAtMs());
            return b.array();
        }
    }

    private static Message decodeMessage(byte[] buf) {
        ByteBuffer b = ByteBuffer.wrap(buf);
        byte tag = b.get();
        if (tag==1) {
            int n = b.getInt();
            byte[] tb = new byte[n]; b.get(tb);
            long exp = b.getLong();
            return Message.text(new String(tb, java.nio.charset.StandardCharsets.UTF_8), exp);
        } else {
            int mlen = b.getShort() & 0xFFFF;
            byte[] mime = new byte[mlen]; b.get(mime);
            int n = b.getInt();
            byte[] db = new byte[n]; b.get(db);
            long exp = b.getLong();
            return Message.file(new String(mime, java.nio.charset.StandardCharsets.UTF_8), db, exp);
        }
    }

    private static byte[] concat(byte[]... arrs) {
        int len = 0;
        for (byte[] a: arrs) len += (a==null?0:a.length);
        byte[] out = new byte[len]; int p=0;
        for (byte[] a: arrs) if (a!=null) { System.arraycopy(a,0,out,p,a.length); p+=a.length; }
        return out;
    }

    // NOTE: To keep SecureChannel pure, inject a signer or pass private key in constructor.
    // Replace cryptoKeyFinder with DI in your project (left as a simplification point).
    private static class cryptoKeyFinder {
        private static java.security.PrivateKey findEdPrivate() {
            throw new IllegalStateException("Inject Ed25519 private key into SecureChannel constructor and store it.");
        }
    }
}
