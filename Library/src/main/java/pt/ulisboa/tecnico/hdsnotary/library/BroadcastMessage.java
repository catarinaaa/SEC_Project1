package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class BroadcastMessage implements Serializable {

    private final String goodId;
    private final String writerId;
    private final String newOwner;
    private final Boolean forSale;
    private final int timeStamp;

    private List<String> echoServers = Collections.synchronizedList(new ArrayList<>());
    private List<String> readyServers = Collections.synchronizedList(new ArrayList<>());
    private List<String> deliveredServers = Collections.synchronizedList(new ArrayList<>());


    public BroadcastMessage(String goodId, Boolean forSale, String writerId, String newOwner, int timeStamp) {
        this.goodId = goodId;
        this.forSale = forSale;
        this.writerId = writerId;
        this.timeStamp = timeStamp;
        this.newOwner = newOwner;
    }

    public String getGoodId() {
        return goodId;
    }

    public String getWriterId() {
        return writerId;
    }

    public String getNewOwner() {
        return newOwner;
    }

    public Boolean getForSale() {
        return forSale;
    }

    public int getTimeStamp() {
        return timeStamp;
    }

    public void addEchoServer(String serverId) {
        echoServers.add(serverId);
    }

    public void addReadyServer(String serverId) {
        readyServers.add(serverId);
    }

    public void addDeliveredServer(String serverId) {
        deliveredServers.add(serverId);
    }

    public boolean checkEchoServer(String serverId) {
        return echoServers.contains(serverId);
    }

    public boolean checkReadyServer(String serverId) {
        return readyServers.contains(serverId);
    }

    public boolean checkDeliveredServer(String serverId) {
        return deliveredServers.contains(serverId);
    }

    public int echoServersSize() {
        return echoServers.size();
    }

    public int readyServersSize() {
        return readyServers.size();
    }

    public int deliveredServersSize() {
        return deliveredServers.size();
    }

    public List<String> getEchoServers() {
        return echoServers;
    }

    public List<String> getReadyServers() {
        return readyServers;
    }

    public List<String> getDeliveredServers() {
        return deliveredServers;
    }

    public void setEchoServers(List<String> echoServers) {
        this.echoServers = echoServers;
    }

    public void setReadyServers(List<String> readyServers) {
        this.readyServers = readyServers;
    }

    public void setDeliveredServers(List<String> deliveredServers) {
        this.deliveredServers = deliveredServers;
    }

    @Override
    public int hashCode() {
        return Objects.hash(goodId, writerId, newOwner, forSale, timeStamp);
    }

    @Override
    public boolean equals(Object o) {
        BroadcastMessage other = (BroadcastMessage) o;
        return other.goodId.equals(this.goodId) && other.forSale.equals(this.forSale) && other.timeStamp == this.timeStamp && other.newOwner.equals(this.newOwner);
    }

    @Override
    public String toString() {
        return "BroadcastMessage{" +
                "goodId='" + goodId + '\'' +
                ", writerId='" + writerId + '\'' +
                ", newOwner='" + newOwner + '\'' +
                ", forSale=" + forSale +
                ", timeStamp=" + timeStamp +
                ", echoServers=" + echoServers +
                ", readyServers=" + readyServers +
                ", deliveredServers=" + deliveredServers +
                '}';
    }
}
