package model;

public class Message {
    private final boolean text;
    private final String mime;
    private final String textPayload;
    private final byte[] dataPayload;
    private final long expiresAtMs;

    private Message(boolean text, String mime, String t, byte[] d, long exp) {
        this.text = text; this.mime = mime; this.textPayload = t; this.dataPayload = d; this.expiresAtMs = exp;
    }

    public static Message text(String t, long exp) { return new Message(true, "text/plain", t, null, exp); }
    public static Message file(String mime, byte[] d, long exp) { return new Message(false, mime, null, d, exp); }

    public boolean isText() { return text; }
    public String getMime() { return mime; }
    public String getText() { return textPayload; }
    public byte[] getData() { return dataPayload; }
    public long getExpiresAtMs() { return expiresAtMs; }
}
