package com.modes;

import javax.xml.bind.DatatypeConverter;

import com.blockcipher.aes.AES128;

/**
 * 8-bit CFB
 * @author ZhengYang
 *
 */
public class CFB {
	public static byte[] IV = {
			(byte)0x0f, (byte)0x15, (byte)0x71, (byte)0xC9,
			(byte)0x47, (byte)0xd9, (byte)0xe8, (byte)0x59,
			(byte)0x0c, (byte)0xb7, (byte)0xad, (byte)0xd6,
			(byte)0xaf, (byte)0x7f, (byte)0x67, (byte)0x98
	};

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

	public static String cfbEncrypt(String plaintext) {

		String ciphertext = "";
		byte[] data = AES128.strToByte(plaintext);
		byte[] pt;
		byte[] prev = new byte[16]; // previous cipher text block
		// padding
		if (data.length % 2 != 0) {
			int count = data.length / 2;
			pt = new byte[2 * (count + 1)];
			for (int i = 0; i < data.length; i++) {
				pt[i] = data[i];
			}
		} else {
			pt = new byte[data.length];
			pt = data;
		}
		// encrypt
		for (int i = 0; i < pt.length; i += 2) {

			// get key stream
			byte[][] state;
			if (i == 0) {
				state = AES128.byteToState(IV);
			} else {
				state = AES128.byteToState(prev);
			}
			AES128.setOriginalKey(key);
			state = AES128.aesEncrypt(state);
			prev = AES128.matrixToArray(state);

			byte[] block = new byte[2];
			for (int j = 0; j < 2; j++) {
				block[j] = pt[i + j];
			}

			// XOR IV/C'
			for (int k = 0; k < 2; k++) {
				block[k] ^= prev[k]; // previous cipher text block
			}
			for(int k = 0; k < 15; k++){
				prev[k] = prev[k + 1];
			}
			for(int k = 0; k < 15; k++){
				prev[k] = prev[k + 1];
			}
			prev[14] = block[0];
			prev[15] = block[1];

			ciphertext += toHexString(block);
		}

		return ciphertext;
	}

	public static String cfbDecrypt(String ciphertext) {
		byte[] ct = toByteArray(ciphertext);
		byte[] pt = new byte[ct.length];
		byte[] prev = new byte[16]; // previous cipher text block
		byte[][] state;
		// encrypt
		for (int i = 0; i < ct.length; i += 2) {
			// get key stream
			if (i == 0) {
				state = AES128.byteToState(IV);
			} else {
				state = AES128.byteToState(prev);
			}
			AES128.setOriginalKey(key);
			state = AES128.aesEncrypt(state);
			prev = AES128.matrixToArray(state);

			byte[] block = new byte[2];
			for (int j = 0; j < 2; j++) {
				block[j] = ct[i + j];
			}

			// XOR C'
			for (int k = 0; k < 2; k++) {
				pt[i + k] = (byte) (block[k] ^ prev[k]); // previous cipher text block
			}
			for(int k = 0; k < 15; k++){
				prev[k] = prev[k + 1];
			}
			for(int k = 0; k < 15; k++){
				prev[k] = prev[k + 1];
			}
			prev[14] = block[0];
			prev[15] = block[1];
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
		String plain = "abc123123123nxajshhsdksadkjhcjhxjcbnzmxc";
		System.out.print("plain text:");
		String origin = AES128.stringToHexString(plain);
		System.out.println(origin);

		String ct = cfbEncrypt(plain);
		System.out.println("after encryption:" + ct);

		String pt = cfbDecrypt(ct);
		System.out.print("after decryption:");
		System.out.println(pt);

	}

}
