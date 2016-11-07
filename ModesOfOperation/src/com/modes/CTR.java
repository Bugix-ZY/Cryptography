package com.modes;

import javax.xml.bind.DatatypeConverter;

import com.blockcipher.aes.AES128;

public class CTR {
	public static int counter = 2354761;
	
	public static byte[] key = {
			(byte)0x0f, (byte)0x15, (byte)0x71, (byte)0xC9,
			(byte)0x47, (byte)0xd9, (byte)0xe8, (byte)0x59,
			(byte)0x0c, (byte)0xb7, (byte)0xad, (byte)0xd6,
			(byte)0xaf, (byte)0x7f, (byte)0x67, (byte)0x98
	};
	
	
	
	/*-------------------------------------------*/
	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}
	
	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
	/*-------------------------------------------*/
	
	
	public static String ctrEncrypt(String plaintext) {
		int count = counter;
		//use counter and key to generate key stream
		String hexCount = null;
		String ciphertext = "";
		byte[] plainCount = null;
		byte[] pt = AES128.strToByte(plaintext);
		int num = pt.length / 16;
		int remain = pt.length % 16;
		byte[] rm = new byte[remain];
		
		//encryption
		for(int i = 0; i < pt.length; i += 16){
			//
			hexCount = Integer.toHexString(count);
			plainCount = toByteArray(hexCount);
			byte[] partialCount = toByteArray(hexCount);
			byte[] padCount = new byte[16];
			for(int j = 0; j < partialCount.length; j++){
				padCount[j] = partialCount[j];
			} 
			// get key stream
			byte[][] state = AES128.byteToState(padCount);
			AES128.setOriginalKey(key);
			state = AES128.aesEncrypt(state);
			byte[] keyStream = AES128.matrixToArray(state);
			
			// divide plain text
			byte[] block = new byte[16];
			if(i / 16 < num){
				for(int j = 0; j < 16; j++){
					block[j] = pt[i + j];
				}
			} else {
				for(int j = 0; j < remain; j++){
					rm[j] = pt[i + j];
				}
			}
			//XOR
			if(i / 16 < num){
				for(int j = 0; j < 16; j++){
					block[j] ^= keyStream[j];
				}
			} else {
				for(int j = 0; j < remain; j++){
					rm[j] ^= keyStream[j];
				}
			}
			//strcat
			if(i / 16 < num){
				ciphertext += toHexString(block);
			} else {
				ciphertext += toHexString(rm);
				//System.out.println(toHexString(rm));
			}
			count += 1;
		}
		return ciphertext;
	}
	
	public static String ctrDecrypt(String ciphertext) {
		int count = counter;
		//use counter and key to generate key stream
		String hexCount = null;
		byte[] plainCount = null;
		byte[] ct = toByteArray(ciphertext);
		int num = ct.length / 16;
		int remain = ct.length % 16;
		byte[] rm = new byte[remain];
		byte pt[] = new byte[ct.length];
		//encryption
		for(int i = 0; i < ct.length; i += 16){
			hexCount = Integer.toHexString(count);
			plainCount = toByteArray(hexCount);
			byte[] partialCount = toByteArray(hexCount);
			byte[] padCount = new byte[16];
			for(int j = 0; j < partialCount.length; j++){
				padCount[j] = partialCount[j];
			} 
			// get key stream
			byte[][] state = AES128.byteToState(padCount);
			AES128.setOriginalKey(key);
			state = AES128.aesEncrypt(state);
			byte[] keyStream = AES128.matrixToArray(state);
			
			// divide cipher text
			byte[] block = new byte[16];
			if(i / 16  < num){
				for(int j = 0; j < 16; j++){
					block[j] = ct[i + j];
				}
			} else {
				for(int j = 0; j < remain; j++){
					rm[j] = ct[i + j];
				}
			}
			//XOR
			if(i / 16 < num){
				for(int j = 0; j < 16; j++){
					block[j] ^= keyStream[j];
				}
			} else {
				for(int j = 0; j < remain; j++){
					rm[j] ^= keyStream[j];
				}
			}
			
			//strcat
			if(i / 16 < num){
				for(int j = 0; j < 16; j++){
					pt[i + j] = block[j];
				}
			} else {
				for(int j = 0; j < remain; j++){
					pt[i + j] = rm[j];
				}
			}
			
			count += 1;
		}
		return new String(pt);
	}

	
	
	public static void main(String[] args) {
		
		String plain = "opera2l.";
		System.out.print("plain text:");
		String origin = AES128.stringToHexString(plain);
		System.out.println(origin);

		String ct = ctrEncrypt(plain);
		System.out.println("after encryption:" + ct);

		String pt = ctrDecrypt(ct);
		System.out.print("after decryption:");
		System.out.println(pt);
	}
}
