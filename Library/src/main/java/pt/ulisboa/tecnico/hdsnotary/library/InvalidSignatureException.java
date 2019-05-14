package pt.ulisboa.tecnico.hdsnotary.library;

public class InvalidSignatureException extends Throwable {
    public InvalidSignatureException(String id) {
        super("ERROR: Signature of " + id + " could not be verified");
    }
}
