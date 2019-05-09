package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;

public class StateOfGoodException extends Exception implements Serializable {
    public StateOfGoodException(String goodId) {
        super("ERROR getting state of " + goodId);
    }
}
