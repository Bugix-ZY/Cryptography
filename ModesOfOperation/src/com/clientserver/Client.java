package com.clientserver;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import com.lloseng.ocsf.client.*;
import com.modes.*;
import com.clientserver.*;


public class Client extends AbstractClient{
	public enum Modes {
	    ECBM, CBCM, CFBM, OFBM,CTRM;
	}
	public static String DEFAULT_HOST = "140.116.194.161";
	public static int DEFAULT_PORT = 5555;
	public Modes mode = Modes.ECBM;

	/*---------------------------------------------------*/
	public Client(){
		super(DEFAULT_HOST, DEFAULT_PORT);
	}
	public Client(String host, int port) {
		super(host, port);
	}
	
	/*---------------------------------------------------*/
	@Override
	protected void connectionEstablished() {
		System.out.println("connection has been Established" );
	}
	
	@Override
	protected void connectionClosed() {
		System.out.println("connection has been Closed");
	}
	
	@Override
	protected void handleMessageFromServer(Object msg) {
		//System.out.println(msg);
	}


	public void setMode(Modes mode) {
		this.mode = mode;
	}
	
	/*---------------------------------------------------*/
	public static void main(String[] args) {
		Client c1 = new Client();
		try {
			c1.openConnection();
			

//			c1.setMode(Modes.ECBM);
//			c1.setMode(Modes.CBCM);
			c1.setMode(Modes.CFBM);
//			c1.setMode(Modes.OFBM);
//			c1.setMode(Modes.CTRM);

			// send msg
			System.out.println(String.format("=========== %s ============", c1.mode));
			BufferedReader csm = new BufferedReader(new InputStreamReader(System.in,"UTF-8"));
            String clientSendMessage = null;
            String ciphertext = null;
			while(!(clientSendMessage = csm.readLine()).equals("exit")){
				switch(c1.mode){
				case ECBM:
					ciphertext = ECB.ecbEncrypt(clientSendMessage);
					break;
				case CBCM:
					ciphertext = CBC.cbcEncrypt(clientSendMessage);
					break;
				case CFBM:
					ciphertext = CFB.cfbEncrypt(clientSendMessage);
					break;
				case OFBM:
					ciphertext = OFB.ofbEncrypt(clientSendMessage);
					break;
				case CTRM:
					ciphertext = CTR.ctrEncrypt(clientSendMessage);
					break;
				}
				System.out.println("send ciphertext[" + ciphertext  +  "] to the server");
				c1.sendToServer(ciphertext);
			}
			c1.closeConnection();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


}
