package com.clientserver;

import java.io.IOException;

import com.clientserver.Client.Modes;
import com.lloseng.ocsf.server.*;
import com.modes.*;

public class Server extends AbstractServer{
	public enum Modes {
	    ECBM, CBCM, CFBM, OFBM,CTRM;
	}
	public final static int DEFAULT_PORT = 5555;
	public Modes mode = Modes.ECBM;
	
	/*---------------------------------------------------*/
	public Server() {
		super(DEFAULT_PORT);
	}
	 
	public Server(int port) {
		super(port);
	}
	
	/*---------------------------------------------------*/

	@Override
	protected void handleMessageFromClient(Object msg, ConnectionToClient client) {
		String pt = null;
		switch(mode){
		case ECBM:
			pt = ECB.ecbDecrypt((String) msg);
			break;
		case CBCM:
			pt = CBC.cbcDecrypt((String) msg);
			break;
		case CFBM:
			pt = CFB.cfbDecrypt((String) msg);
			break;
		case OFBM:
			pt = OFB.ofbDecrypt((String) msg);
			break;
		case CTRM:
			pt = CTR.ctrDecrypt((String) msg);
			break;
		}
		System.out.println("Ciphertext" + "[" + msg + "]" +  " from " + client.getInetAddress());
		System.out.println("Plaintext " + "[" + pt + "]");
	    try {
			client.sendToClient("server > " + pt);
		} catch (IOException e) {
			System.out.println("could not send to client");
			e.printStackTrace();
		}
	}

	@Override
	protected void serverStarted() {
		System.out.println("Server listening for connections on port " + getPort());
	}
	
	@Override
	protected void serverClosed() {
		System.out.println
	      ("Server has stopped listening for connections.");
	}
	
	@Override
	protected void clientConnected(ConnectionToClient client) {
		System.out.println("client " + client.getName() + " has connected.");
		System.out.println("Server.getNumberOfClients()="+getNumberOfClients());
	}

	
	public void setMode(Modes m) {
		mode = m;
	}

	/*---------------------------------------------------*/
	public static void main(String[] args) {
		Server sv = new Server();
//		sv.setMode(Modes.ECBM);
//		sv.setMode(Modes.CBCM);
		sv.setMode(Modes.CFBM);
//		sv.setMode(Modes.OFBM);
//		sv.setMode(Modes.CTRM);
		try {
			sv.listen();
		} catch (IOException e) {
			System.out.println("Could not listen for clients!");
			e.printStackTrace();
		}
	}

}
