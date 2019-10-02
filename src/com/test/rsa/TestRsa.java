package com.test.rsa;

import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

class Base64Coded {
//	public static void main(String[] args) {
//		String string = "qianyang123";
//		//����
//		String encode = encode(string.getBytes());
//		System.out.println(string + "\t�������ַ���Ϊ��" + encode);
//		//����
//		String decode = decode(encode.getBytes());
//		System.out.println(encode + "\t�ַ��������Ϊ��" + decode);
//	}
	//base64 ����
    public static String decode(byte[] bytes) {  
        return new String(Base64.decodeBase64(bytes));  
    }  
  
    //base64 ����
    public static String encode(byte[] bytes) {  
        return new String(Base64.encodeBase64(bytes));  
    }  
}

public class TestRsa {

	Map<Integer, String> keyMap = new HashMap<Integer, String>(); // ���ڷ�װ��������Ĺ�Կ��˽Կ

	public static void main(String[] args){
		// ���ɹ�Կ��˽Կ
		Map<Integer, String> keyMap = new HashMap<Integer, String>(); 
		try {
			genKeyPair(keyMap);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// �����ַ���
		String message = "df723820";
		System.out.println("������ɵĹ�ԿΪ:" + keyMap.get(0));
		System.out.println("������ɵ�˽ԿΪ:" + keyMap.get(1));
		String messageEn;
		String messageDe;
		try {
			messageEn = encrypt(message, keyMap.get(0));
			System.out.println(message + "\n���ܺ���ַ���Ϊ:" + messageEn);
			messageDe= decrypt(messageEn, keyMap.get(1));
			System.out.println("��ԭ����ַ���Ϊ:" + messageDe);
			
			String a = privateKeyEncrypt(message,keyMap.get(1));
			System.out.println("--------"+a);
			String b = publicKeydecrypt(a, keyMap.get(0));
			System.out.println(b);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	/**
	 * ���������Կ��
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public static void genKeyPair(Map<Integer, String> keyMap) throws NoSuchAlgorithmException {
		// KeyPairGenerator���������ɹ�Կ��˽Կ�ԣ�����RSA�㷨���ɶ���
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		// ��ʼ����Կ������������Կ��СΪ96-1024λ
		keyPairGen.initialize(1024, new SecureRandom());
		// ����һ����Կ�ԣ�������keyPair��
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate(); // �õ�˽Կ
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic(); // �õ���Կ
		String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
		// �õ�˽Կ�ַ���
		String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
		// ����Կ��˽Կ���浽Map
		keyMap.put(0, publicKeyString); // 0��ʾ��Կ
		keyMap.put(1, privateKeyString); // 1��ʾ˽Կ
	}

	/**
	 * RSA��Կ����
	 * 
	 * @param str       �����ַ���
	 * @param publicKey ��Կ
	 * @return ����
	 * @throws Exception ���ܹ����е��쳣��Ϣ
	 */
	public static String encrypt(String str, String publicKey) throws Exception {
		// base64����Ĺ�Կ
		byte[] decoded = Base64.decodeBase64(publicKey);
		RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(decoded));
		// RSA����
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
		return outStr;
	}

	/**
	 * RSA˽Կ����
	 * 
	 * @param str        �����ַ���
	 * @param privateKey ˽Կ
	 * @return ����
	 * @throws Exception ���ܹ����е��쳣��Ϣ
	 */
	public static String decrypt(String str, String privateKey) throws Exception {
		// 64λ������ܺ���ַ���
		byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
		// base64�����˽Կ
		byte[] decoded = Base64.decodeBase64(privateKey);
		RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
				.generatePrivate(new PKCS8EncodedKeySpec(decoded));
		// RSA����
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, priKey);
		String outStr = new String(cipher.doFinal(inputByte));
		return outStr;
	}
	/**
	 * RSA˽Կ����
	 * @param str        �����ַ���
	 * @param privateKey ˽Կ
	 * @return ����
	 * @throws Exception ���ܹ����е��쳣��Ϣ
	 */
	public static String privateKeyEncrypt(String str, String privateKey) throws Exception {
		// base64�����˽Կ
		byte[] decoded = Base64.decodeBase64(privateKey);
		RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
				.generatePrivate(new PKCS8EncodedKeySpec(decoded));
		// RSA����
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, priKey);
		String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
		return outStr;
		
	}
	
	/**
	 * RSA��Կ����
	 * @param str       �����ַ���
	 * @param publicKey ��Կ
	 * @return ����
	 * @throws Exception ���ܹ����е��쳣��Ϣ
	 */
	public static String publicKeydecrypt(String str, String publicKey) throws Exception {
		// 64λ������ܺ���ַ���
		byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
		// base64����Ĺ�Կ
		byte[] decoded = Base64.decodeBase64(publicKey);
		RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(decoded));
		// RSA����
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, pubKey);
		String outStr = new String(cipher.doFinal(inputByte));
		return outStr;
	}
}


