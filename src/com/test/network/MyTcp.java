package com.test.network;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.Data;

import org.apache.commons.codec.digest.DigestUtils;

import com.test.rsa.TestDes;
import com.test.rsa.TestRsa;
import com.test.swing.TestZip;
import com.test.swing.ToSerialize;

public class MyTcp {

	private BufferedReader reader;
	private ServerSocket server;
	private Socket socket;
	String ClientPublicKey;
	Map<Integer, String> keyMap;
	private FileInputStream fis;  
    private DataOutputStream dos; 
    
	public static void main(String[] args) {
		MyTcp tcp = new MyTcp();
		tcp.getserver();
	}

	private void getserver() {
		try {
			server = new ServerSocket(8998);
			System.out.println("�������׽����Ѿ������ɹ�");
			keyMap = new HashMap<Integer, String>();
			TestRsa.genKeyPair(keyMap);
			System.out.println("���ɹ�Կ��˽Կ��"+keyMap.get(0)+" "+keyMap.get(1));
			while (true) {
				System.out.println("�ȴ��ͻ�������");
				socket = server.accept();
				reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				ClientPublicKey = reader.readLine();
				System.out.println("�ͻ��˹�ԿΪ"+ClientPublicKey);
				getClientMessage();
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
	}

 
	private void getClientMessage() {
		try {
			while (true) {
				String fileName = reader.readLine();
				System.out.println(fileName);
				File sourceFile = new File("C:\\Socket\\" + fileName);
				if (sourceFile.exists()&& fileName!=null &&fileName.length()!=0) {
					System.out.println("�ļ�����");
					
					
					
					//����DES��Կ�������ļ�
					String fileDESpath = "C:\\Socket\\" + fileName+".DES";
					//TestDes td = new TestDes("aaa"+Math.random());
					String seed = new SimpleDateFormat("yyyyMMdd_HH_mm_ss").format(new Date())+Math.random();
					TestDes td = new TestDes(seed);
					System.out.println("�������Ϊ��"+seed);
					td.encrypt("C:\\Socket\\" + fileName, fileDESpath);
					
					//�ÿͻ��˹�Կ����DES��Կ���Ѽ��ܹ�����Կ���л����ļ�
					String keyEncryPath = "C:\\Socket\\" +fileName+".DES.key.RSAencry";
					String encryptKey = TestRsa.encrypt(seed, ClientPublicKey);
					ToSerialize.SerializeString(encryptKey, keyEncryPath);
					
					//����ԭ�ļ���MD5����˽Կ���ܣ��Ѽ��ܺ��md5���л�Ϊ�ļ�
					String md5EncryPath = "C:\\Socket\\" +fileName+".md5.RSAencry";
					String md5 = DigestUtils.md5Hex(new FileInputStream("C:\\Socket\\"+fileName));
					String md5Encry = TestRsa.privateKeyEncrypt(md5, keyMap.get(1));
					ToSerialize.SerializeString(md5Encry, md5EncryPath);
					
					//�������
					File md5EncryFile = new File(md5EncryPath);
					File keyEncryFile = new File(keyEncryPath);
					File DESFile = new File(fileDESpath);
					File srcFile[] = {DESFile,keyEncryFile,md5EncryFile};
					File zipFile = new File("C:\\Socket\\"+fileName+".zip");
					TestZip.zipFiles(srcFile, zipFile);
					
					File file = zipFile;
					fis = new FileInputStream(file);
					dos = new DataOutputStream(socket.getOutputStream());
					//���͹�Կ
					dos.writeUTF(keyMap.get(0));
					// �ļ����ͳ���
					dos.writeUTF(file.getName());
					dos.flush();
					dos.writeLong(file.length());
					dos.flush();
					
					// ��ʼ�����ļ�
					System.out.println("======== ��ʼ�����ļ� ========");
					byte[] bytes = new byte[1024];
					int length = 0;
					long progress = 0;
					
					while ((length = fis.read(bytes, 0, bytes.length)) != -1) {
						String a = new String(bytes);
						dos.write(bytes, 0, length);
						dos.flush();
						progress += length;
						System.out.println("| " + (100 * progress / file.length()) + "% |");
					}
					System.out.println("======== �ļ�����ɹ� ========");
				}else {
					dos = new DataOutputStream(socket.getOutputStream());
					String NotFount = "NotFount";
					System.out.println(NotFount);
					dos.writeUTF(NotFount);
				}
			}
		} catch (Exception e) {
			System.err.println("�ͻ����˳�����");
		}
		try {
			if (reader != null)
				reader.close();
			if (socket != null)
				socket.close();
			if(fis != null)  
                fis.close();  
            if(dos != null)  
                dos.close();  
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
