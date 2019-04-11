package pt.ulisboa.tecnico.hdsnotary.client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
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
	
	private Map<String, String> nounceList = new HashMap<>();

	public User(String id, NotaryInterface notary, String user2, String user3) throws RemoteException, KeyStoreException {

		this.id = id;
		this.notary = notary;
		this.user2 = user2;
		this.user3 = user3;

		goods = new HashMap<String, Boolean>();
		
		System.out.println("Initializing User");

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

	@Override
	public String getNounce(String userId, byte[] signature) {
		
		String nounce = cryptoUtils.generateCNounce();
		nounceList.put(userId, nounce);
		return nounce;
	}
	
	public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b));
		   return sb.toString();
		}
	
	@Override
	public Boolean buyGood(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException {

		String nounceToNotary = cryptoUtils.generateCNounce();
		String data = notary.getNounce(this.id) + nounceToNotary + this.id + userId + goodId;

		byte[] signature2 = cryptoUtils.signMessage(data);
		System.out.println("Data: " + data);
		
		Result result = notary.transferGood(this.getId(), userId, goodId, nounceToNotary, signature2);
		

		System.out.println("> " + data + result.getResult());

		if (cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
			System.out.println("Signature verified! Notary confirmed buy good");
			goods.remove(goodId);
			return result.getResult();
		}
		else {
			System.err.println("ERROR: Signature does not verify");
			return false;
		}
	}
	
	public boolean buying(String goodId) throws RemoteException {
		Result stateOfGood = stateOfGood(goodId);
		if (stateOfGood == null || false == stateOfGood.getResult()) {
			System.out.println("Good is not up for sale");
			return false;
		}
		else {
			String seller = stateOfGood.getUserId();
			
			if(remoteUser2 == null || remoteUser3 == null) {
				lookUpUsers();
			}
			
			Boolean result = false;
			
			if(seller.equals(user2) && remoteUser2 != null) {
				
				String nounce = remoteUser2.getNounce(this.id, cryptoUtils.signMessage(this.id));
				String cnounce = cryptoUtils.generateCNounce();
				nounceList.put(user2, cnounce);
				String toSign = nounce + cnounce + this.id + goodId;
				result = remoteUser2.buyGood(this.id, goodId, cnounce, cryptoUtils.signMessage(toSign));
			}
			else if(seller.equals(user3) && remoteUser3 != null) {
				String nounce = remoteUser3.getNounce(this.id, cryptoUtils.signMessage(this.id));
				String cnounce = cryptoUtils.generateCNounce();
				nounceList.put(user3, cnounce);
				String toSign = nounce + cnounce + this.id + goodId;
				result = remoteUser3.buyGood(this.id, goodId, cnounce, cryptoUtils.signMessage(toSign));
			}
			
			if(result) {
				goods.put(goodId, false);
				System.out.println(goodId + "was add to the list of goods!");
			}
			
			return false;
		}
	}

	public boolean intentionSell(String goodId) {
		try {
			String nounce = notary.getNounce(this.id);
			String cnounce = cryptoUtils.generateCNounce();
			String data = nounce + cnounce + this.id + goodId;
			Result result = notary.intentionToSell(this.id, goodId, cnounce, cryptoUtils.signMessage(data));
			
			if (result != null && cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed intention to sell");
				goods.replace(goodId, true);
				System.out.println("Result: " + goodId + " is now for sale");
				return result.getResult();
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				return false;
			}
		} catch (RemoteException e) {
			// TODO Auto-generated catch block
			return false;
		}
	}
	
	public Result stateOfGood(String goodId) {
		try {
			String cnounce = cryptoUtils.generateCNounce();
			String data = notary.getNounce(this.id) + cnounce + this.id + goodId;
			
			System.out.println("DATA: " + data);
	
			Result result = notary.stateOfGood(this.getId(), cnounce, goodId, cryptoUtils.signMessage(data));
	
			System.out.println("> " + data + result.getResult());
	
			if (cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed state of good message");
				System.out.println("For sale: " + result.getResult() +"\n");
				return result;
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				return result;
			}
		} catch(RemoteException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	public void listGoods() {
		for (String goodId: goods.keySet()){
			Boolean value = goods.get(goodId);
            System.out.println(goodId + " --> For sale: " + value);
		} 
	}
	
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
