package io.github.peppe289.security_gatekeeper.gateway.forward;

/**
 * The request could not be forwarded. {@link #status()} is the HTTP status the
 * gateway answers with: 400 (request not representable upstream),
 * 502 (upstream unreachable / protocol error) or 504 (upstream timeout).
 */
public class ForwardingException extends Exception {

    private final int status;

    public ForwardingException(int status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public int status() {
        return status;
    }
}
