package com.modes;

import javax.xml.bind.DatatypeConverter;
import com.blockcipher.aes.AES128;

/**
 * electronic code book mode
 * 
 * @author ZhengYang
 *
 */
public class ECB {
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
	
	public static String ecbEncrypt(String plaintext) {
		
		String ciphertext = "";
		byte[] data = AES128.strToByte(plaintext);
		byte[] pt;
		
		//padding
		if(data.length % 16 != 0){
			int count = data.length / 16;
			int pad = 16 - data.length % 16;
			pt = new byte[16 * (count + 1)];
			for(int i = 0; i < data.length; i++){
				pt[i] = data[i];
			}
		} else {
			pt = new byte[data.length];
			pt = data;
		}
		//encrypt
		for (int i = 0; i < pt.length; i += 16) {
			byte[] block = new byte[16];
			for(int j = 0; j < 16; j++){
				block[j] = pt[i + j];
			}
			byte[][] state = AES128.byteToState(block);
			AES128.setOriginalKey(key);
			state = AES128.aesEncrypt(state);
			byte[] t = AES128.matrixToArray(state);
			ciphertext += toHexString(t);
		}
		
		return ciphertext;
	}
	
	public static String ecbDecrypt(String ciphertext) {
		//byte pt[] = new byte[ciphertext.length() / 2];
		byte[] data = toByteArray(ciphertext);
		byte[] pt = new byte[data.length];
		//System.out.println(data.length);
		for (int i = 0; i < data.length; i += 16) {
			byte[] block = new byte[16];
			for(int j = 0; j < 16; j++){
				block[j] = data[i + j];
			}
			byte[][] state = AES128.byteToState(block);
			AES128.setOriginalKey(key);
			state = AES128.aesDecrpyt(state);
			byte[] t = AES128.matrixToArray(state);
			for(int j = 0; j < 16; j++){
				pt[i + j] = t[j];
			}
		}
		
		return new String(pt);
	}
	/*-------------------------------------------*/
	public static byte[] getKey() {
		return key;
	}

	public static void setKey(byte[] key) {
		ECB.key = key;
	}
	/*-------------------------------------------*/
	
	public static void main(String[] args) {
		String plain = "njid";
		String ct = ecbEncrypt(plain);
		System.out.println("after encryption:"  + ct);

		String pt = ecbDecrypt(ct);
		System.out.print("after decryption:" );
		System.out.println(pt);
		
	}


}
