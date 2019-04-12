package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.Map;

import pt.ulisboa.tecnico.hdsnotary.library.CryptoUtilities;
import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;
import pt.ulisboa.tecnico.hdsnotary.library.Result;
import pt.ulisboa.tecnico.hdsnotary.library.UserInterface;

public class User extends UnicastRemoteObject implements UserInterface {
	
	private static final long serialVersionUID = 1L;

	private static final String NOTARY_ID = "Notary";

	private final String id;
	private final String user2;
	private final String user3;
	private UserInterface remoteUser2 = null;
	private UserInterface remoteUser3 = null;
	// List of all goods possessed
	private Map<String, Boolean> goods;
	// Instance of remote Notary Object
	private NotaryInterface notary = null;

	
	private String keysPath; // KeyStore location
	private String password; // KeyStore password
	
	CryptoUtilities cryptoUtils;
	
	private Map<String, String> nonceList = new HashMap<>();

	public User(String id, NotaryInterface notary, String user2, String user3) throws RemoteException, KeyStoreException {

		this.id = id;
		this.notary = notary;
		this.user2 = user2;
		this.user3 = user3;

		goods = new HashMap<String, Boolean>();
		
		this.keysPath = "Client/storage/" + id + ".p12";
		this.password = id + "1234";

		goods = new HashMap<String, Boolean>();

		cryptoUtils = new CryptoUtilities(this.id, this.keysPath, this.password);
		
		System.out.println("Initializing user " + id);

	}

	public String getUser2() {
		return user2;
	}

	public String getUser3() {
		return user3;
	}

	public String getId() {
		return id;
	}

	public Map<String, Boolean> getGoods() {
		return goods;
	}
	
	public void addGood(String goodId, boolean bool) {
		goods.put(goodId, bool);
	}

	/*
	 * Function to obtain a nonce for communication
	 * Invoked before executing any other method
	 */
	@Override
	public String getNonce(String userId, byte[] signature) {
		
		String nonce = cryptoUtils.generateCNonce();
		nonceList.put(userId, nonce);
		return nonce;
	}

	/*
	 * Invoked when another user is buying a good that this user owns
	 */
	@Override
	public Boolean buyGood(String userId, String goodId, String cnonce, byte[] signature) throws IOException {

		String nonceToNotary = cryptoUtils.generateCNonce();
		String data = notary.getNonce(this.id) + nonceToNotary + this.id + userId + goodId;

		byte[] signature2 = cryptoUtils.signMessage(data);
		System.out.println("Data: " + data);
		
		Result result = notary.transferGood(this.getId(), userId, goodId, nonceToNotary, signature2);
		

		System.out.println("> " + data + result.getResult());
		
		if (result.getResult() && cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
			System.out.println("Signature verified! Notary confirmed buy good");
			goods.remove(goodId);
			return result.getResult();
		} else if(!result.getResult()) {
			System.out.println("Good cannot be sold");
			return result.getResult();
		}
		else {
			System.err.println("ERROR: Signature does not verify");
			return false;
		}
	}

	/*
	 * Invoked when interacting with the users
	 */
	public boolean buying(String goodId) {
		try {
			Result stateOfGood = stateOfGood(goodId);
			if (stateOfGood == null || false == stateOfGood.getResult()) {
				System.out.println("ERROR: Buying was not possible!");
				System.out.println("------------------");
				return false;
			}
			else {
				String seller = stateOfGood.getUserId();
				
				if(remoteUser2 == null || remoteUser3 == null) {
					lookUpUsers();
				}
				
				Boolean result = false;
				
				if(seller.equals(user2) && remoteUser2 != null) {
					
					String nonce = remoteUser2.getNonce(this.id, cryptoUtils.signMessage(this.id));
					String cnonce = cryptoUtils.generateCNonce();
					nonceList.put(user2, cnonce);
					String toSign = nonce + cnonce + this.id + goodId;
					result = remoteUser2.buyGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
				}
				else if(seller.equals(user3) && remoteUser3 != null) {
					String nonce = remoteUser3.getNonce(this.id, cryptoUtils.signMessage(this.id));
					String cnonce = cryptoUtils.generateCNonce();
					nonceList.put(user3, cnonce);
					String toSign = nonce + cnonce + this.id + goodId;
					result = remoteUser3.buyGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
				}
				
				if(result) {
					goods.put(goodId, false);
					System.out.println("SUCCESSFUL BUY");
					System.out.println(goodId + "was added to the list of goods!");
					System.out.println("------------------");
					return true;
				} else {
					System.out.println("ERROR: Buying was not possible!");
					System.out.println("------------------");
					return false;
				}

			}

		} catch (IOException e) {
			rebind();
			return buying(goodId);
		}
	}

	/*
	 * Invoked when a user wants to sell a good
	 */

	public boolean intentionSell(String goodId) {
		try {
			String nonce = notary.getNonce(this.id);
			String cnonce = cryptoUtils.generateCNonce();
			String data = nonce + cnonce + this.id + goodId;
			Result result = notary.intentionToSell(this.id, goodId, cnonce, cryptoUtils.signMessage(data));
			
			if (result != null && cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
				if(result.getResult()) {
					goods.replace(goodId, true);
					System.out.println("Result: " + goodId + " is now for sale");
				}
				else {
					System.out.println("Result: Invalid good");
				}
				System.out.println("-----------------------------");
				return result.getResult();
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				System.out.println("-----------------------------");
				return false;
			}
		} catch (RemoteException e) {
			rebind();
			return intentionSell(goodId);
		}
	}

	/*
	 * Invoked to get current state of a good, it returns the current owner and if it is for sale or not
	 */
	public Result stateOfGood(String goodId) {
		try {

			String cnonce = cryptoUtils.generateCNonce();
			String data = notary.getNonce(this.id) + cnonce + this.id + goodId;
			
			Result result = notary.stateOfGood(this.getId(), cnonce, goodId, cryptoUtils.signMessage(data));
	
			if (cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
				System.out.println("Owner: " + result.getUserId());
				System.out.println("For sale: " + result.getResult());
				System.out.println("-------------------------");
				return result;
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				System.out.println("-------------------------");
				return null;
			}
		} catch(RemoteException e) {
			rebind();
			return stateOfGood(goodId);
		}
	}

	/*
	 * Invoked when the server crashes and communications between the user and the notary fail
	 */
	public void rebind() {
		try {
        	Registry reg = LocateRegistry.getRegistry(3000);
			this.notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");
            reg.rebind(getId(), this);
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			e.printStackTrace();
		}
	}

	/*
	 * List all current goods
	 */
	public void listGoods() {
		for (String goodId: goods.keySet()){
			Boolean value = goods.get(goodId);
            System.out.println(goodId + " --> For sale: " + value);
		} 
	}

	/*
	 * Finds the remaining users on the RMI registry
	 */
	private void lookUpUsers() {
		System.out.println(getUser2());
		System.out.println(getUser3());
		try {
			remoteUser2 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser2());
			remoteUser3 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser3());
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.err.println("ERROR looking up user");
		}
	}
}
