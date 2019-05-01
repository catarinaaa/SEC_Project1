package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;

public class TransferException extends Exception implements Serializable {

    public TransferException(String s) {
        super(s);
    }
}
