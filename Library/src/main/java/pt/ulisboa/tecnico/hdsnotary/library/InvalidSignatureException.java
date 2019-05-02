package pt.ulisboa.tecnico.hdsnotary.library;

public class InvalidSignatureException extends Throwable {
    public InvalidSignatureException() {
        super("ERROR: Signature could not be verified");
    }
}
