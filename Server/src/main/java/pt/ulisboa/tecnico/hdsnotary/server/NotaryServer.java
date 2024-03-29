package pt.ulisboa.tecnico.hdsnotary.server;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class NotaryServer {

	private static Registry reg;

	public static void main(String[] args) {
		int port = 3000;
		boolean useCC;
		String id;
		boolean verbose = false;
		boolean byzantine = false;
		
			
		if(args.length >= 2 && args.length <= 4) {
			if (args.length == 3)
				verbose = Boolean.parseBoolean(args[2]);
			else if(args.length == 4) {
				verbose = Boolean.parseBoolean(args[2]);
				byzantine = Boolean.parseBoolean(args[3]);
			}

			id = args[0];
			useCC = Boolean.parseBoolean(args[1]);
		}
		else {
			System.out.println("Error in arguments");
			return;
		}


		try {
			NotaryImpl obj = NotaryImpl.getInstance(useCC, id, byzantine);

			reg = LocateRegistry.getRegistry(port);
			reg.rebind(id, obj);
			
			if (verbose) {
				for (String s : reg.list()) {
					System.out.println("> " + s);
				}
			
				System.out.println(id + " is ready!");
	
			}
			
			System.out.println("Awaiting connections");
			System.out.println("Press enter to shutdown");
			
			System.in.read();
			obj.stop();
			reg.unbind(id);
			System.out.println("Server terminated");
			System.exit(0);

		} catch (Exception e) {
			System.err.println("ERROR: Aborting...");
			e.printStackTrace();
			System.exit(1);
		}

	}

}
