package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

public class BroadcastMessage implements Serializable {

	private ConcurrentHashMap<String, Boolean> echo = new ConcurrentHashMap<>();
	private ConcurrentHashMap<String, Boolean> ready = new ConcurrentHashMap<>();
	private ConcurrentHashMap<String, Boolean> delivered = new ConcurrentHashMap<>();

	private byte[] signature;

	public BroadcastMessage(byte[] signature) {
		this.signature = signature;
	}

	public void addEcho(String serverId) {
		echo.put(serverId, true);
	}

	public void addReady(String serverId) {
		ready.put(serverId, true);
	}

	public void addDelivered(String serverId) {
		delivered.put(serverId, true);
	}

	public ConcurrentHashMap<String, Boolean> getEcho() {
		return echo;
	}

	public ConcurrentHashMap<String, Boolean> getReady() {
		return ready;
	}

	public ConcurrentHashMap<String, Boolean> getDelivered() {
		return delivered;
	}

	public boolean getEchoServer(String serverId) {
		return echo.get(serverId);
	}

	public boolean getReadyServer(String serverId) {
		return ready.get(serverId);
	}

	public boolean getDeliveredServer(String serverId) {
		return delivered.get(serverId);
	}

	public byte[] getSignature() {
		return signature;
	}
}
