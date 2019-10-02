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
			System.out.println("服务器套接字已经创建成功");
			keyMap = new HashMap<Integer, String>();
			TestRsa.genKeyPair(keyMap);
			System.out.println("生成公钥和私钥："+keyMap.get(0)+" "+keyMap.get(1));
			while (true) {
				System.out.println("等待客户机连接");
				socket = server.accept();
				reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				ClientPublicKey = reader.readLine();
				System.out.println("客户端公钥为"+ClientPublicKey);
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
					System.out.println("文件存在");
					
					
					
					//生成DES秘钥并加密文件
					String fileDESpath = "C:\\Socket\\" + fileName+".DES";
					//TestDes td = new TestDes("aaa"+Math.random());
					String seed = new SimpleDateFormat("yyyyMMdd_HH_mm_ss").format(new Date())+Math.random();
					TestDes td = new TestDes(seed);
					System.out.println("随机种子为："+seed);
					td.encrypt("C:\\Socket\\" + fileName, fileDESpath);
					
					//用客户端公钥加密DES秘钥，把加密过的秘钥序列化成文件
					String keyEncryPath = "C:\\Socket\\" +fileName+".DES.key.RSAencry";
					String encryptKey = TestRsa.encrypt(seed, ClientPublicKey);
					ToSerialize.SerializeString(encryptKey, keyEncryPath);
					
					//生成原文件的MD5并用私钥加密，把加密后的md5序列化为文件
					String md5EncryPath = "C:\\Socket\\" +fileName+".md5.RSAencry";
					String md5 = DigestUtils.md5Hex(new FileInputStream("C:\\Socket\\"+fileName));
					String md5Encry = TestRsa.privateKeyEncrypt(md5, keyMap.get(1));
					ToSerialize.SerializeString(md5Encry, md5EncryPath);
					
					//打包发送
					File md5EncryFile = new File(md5EncryPath);
					File keyEncryFile = new File(keyEncryPath);
					File DESFile = new File(fileDESpath);
					File srcFile[] = {DESFile,keyEncryFile,md5EncryFile};
					File zipFile = new File("C:\\Socket\\"+fileName+".zip");
					TestZip.zipFiles(srcFile, zipFile);
					
					File file = zipFile;
					fis = new FileInputStream(file);
					dos = new DataOutputStream(socket.getOutputStream());
					//发送公钥
					dos.writeUTF(keyMap.get(0));
					// 文件名和长度
					dos.writeUTF(file.getName());
					dos.flush();
					dos.writeLong(file.length());
					dos.flush();
					
					// 开始传输文件
					System.out.println("======== 开始传输文件 ========");
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
					System.out.println("======== 文件传输成功 ========");
				}else {
					dos = new DataOutputStream(socket.getOutputStream());
					String NotFount = "NotFount";
					System.out.println(NotFount);
					dos.writeUTF(NotFount);
				}
			}
		} catch (Exception e) {
			System.err.println("客户机退出连接");
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
