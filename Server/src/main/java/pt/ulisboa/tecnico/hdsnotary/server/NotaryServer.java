package pt.ulisboa.tecnico.hdsnotary.server;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.ArrayList;
import java.util.TreeMap;

public class NotaryServer {

	public static void main(String[] args) {
		int port = 3000;

		try {
			NotaryImpl obj = NotaryImpl.getInstance();

			Registry reg = LocateRegistry.createRegistry(port);
			reg.rebind("Notary", obj);
			
			System.out.println("Server ready!");

			System.out.println("Awaiting connections");
			System.out.println("Press enter to shutdown");
			System.in.read();
			System.out.println("Server termindated");
			System.exit(0);

		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

	}

}
