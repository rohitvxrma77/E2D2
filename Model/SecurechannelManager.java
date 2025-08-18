package net;

import crypto.EphemeralKeyPair;
import model.Envelope;
import model.Message;
import model.PeerInfo;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SecureChannelManager {
    private final EphemeralKeyPair id;

    public SecureChannelManager(EphemeralKeyPair id) {
        this.id = id;
    }

    public Envelope encryptFor(PeerInfo peer, Message m) {
        SecureChannel ch = new SecureChannel(id.getXPrivate(), id.getEdPublic(), peer.getXPub(), peer.getEdPub());
        // For real DI, modify SecureChannel to accept Ed25519 private key and sign inside encrypt()
        throw new UnsupportedOperationException("Wire up signer: adjust SecureChannel to take Ed25519 SK.");
    }

    public Message tryDecryptFrom(PeerInfo peer, Envelope env) {
        SecureChannel ch = new SecureChannel(id.getXPrivate(), id.getEdPublic(), peer.getXPub(), peer.getEdPub());
        return ch.decrypt(env, id.getXPrivate(), peer.getXPub(), peer.getEdPub());
    }
}
