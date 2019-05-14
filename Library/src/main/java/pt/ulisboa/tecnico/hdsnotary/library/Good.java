package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Good implements Serializable {
    private String userId;
    private String goodId;
    private Boolean forSale;
    private int writeTimestamp;
    private Map<String, Integer> listening;

    public Good(String userId, String goodId) {
        super();
        this.userId = userId;
        this.goodId = goodId;
        this.forSale = false;
        this.writeTimestamp = 0;
        this.listening = new HashMap<>();
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getGoodId() {
        return goodId;
    }

    public void setGoodId(String goodId) {
        this.goodId = goodId;
    }

    public Boolean forSale() {
        return forSale;
    }

    public void setForSale() {
        this.forSale = true;
    }

    public void notForSale() {
        this.forSale = false;
    }

    public int getWriteTimestamp() {
        return writeTimestamp;
    }

    public void setWriteTimestamp(int writeTimestamp) {
        this.writeTimestamp = writeTimestamp;
    }

    public Map<String, Integer> getListening() {
        return listening;
    }

    public void setListener(String id, int readId) {
        listening.put(id, readId);
    }

    @Override
    public String toString() {
        return "GoodID: " + goodId + "\nUserID: " + userId + "\nFor Sale: " + forSale + "\nTimeStamp: " + writeTimestamp;
    }

    @Override
    public int hashCode() {
        return Objects.hash(goodId, userId, forSale, writeTimestamp);
    }

    public boolean removeListener(String id, int readId) {
        if (listening.get(id) == readId) {
            listening.remove(id);
            return true;
        }
        return false;
    }
}
