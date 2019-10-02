package com.test.network;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.math.RoundingMode;
import java.net.Socket;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import org.apache.commons.codec.digest.DigestUtils;

import com.test.rsa.TestDes;
import com.test.rsa.TestRsa;
import com.test.swing.TestZip;
import com.test.swing.ToSerialize;

public class MyClient extends JFrame {
	private PrintWriter writer;
	Socket socket;
	private JTextArea ta = new JTextArea();
	private JTextField tf = new JTextField();
	Container cc; 
	String fileName = "";
	String ServicePublicKey;
	Map<Integer, String> keyMap;
	
	public MyClient(String title) {
		super(title);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		cc = this.getContentPane();
		final JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBorder(new BevelBorder(BevelBorder.RAISED));
		getContentPane().add(scrollPane,BorderLayout.CENTER);
		scrollPane.setViewportView(ta);
		
		cc.add(tf,"South");
		tf.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				fileName = tf.getText();
				writer.println(fileName);
				ta.append("接收文件"+fileName+'\n');
				ta.setSelectionEnd(ta.getText().length());
				tf.setText("");
				new Thread(new Task(socket)).start();  
			}
		});
		
		JButton bl = new JButton("解压解密校验文件");
		bl.setBounds(10,10,100,20);
		bl.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				System.out.println("开始检验文件");
				try {
					//解压文件
					File zipfile = new File("C:\\Socket\\download\\"+fileName+".zip");
					TestZip.unZipFiles(zipfile, "C:\\Socket\\download\\");
					
					//获取加密过的DES秘钥
					String encryptKey = ToSerialize.DeserializeString("C:\\Socket\\download\\" +fileName+".DES.key.RSAencry");
					System.out.println(encryptKey);
					System.out.println(keyMap.get(1));
					
					//使用私钥解密DES秘钥
					String DESKey = TestRsa.decrypt(encryptKey, keyMap.get(1));
					System.out.println("私钥解密获得随机种子为"+DESKey);
					//解密DES加密过的文件
					TestDes td = new TestDes(DESKey);
					td.decrypt("C:\\Socket\\download\\"+fileName+".DES", "C:\\Socket\\download\\"+fileName+".DES.txt"); // 解密
					ta.append("解压并解密成功"+fileName+'\n');
					ta.setSelectionEnd(ta.getText().length());
					
					String md5Encry = ToSerialize.DeserializeString("C:\\Socket\\download\\" +fileName+".md5.RSAencry");
					String md5 =TestRsa.publicKeydecrypt(md5Encry, ServicePublicKey);
					System.out.println("获取md5为："+md5);
					
					String NEWmd5 = DigestUtils.md5Hex(new FileInputStream("C:\\Socket\\download\\"+fileName+".DES.txt"));
					if (md5.equals(NEWmd5)) {
						ta.append("MD5校验成功！"+fileName+'\n');
						ta.setSelectionEnd(ta.getText().length());
					}else {
						ta.append("MD5校验失败！"+fileName+'\n');
						ta.setSelectionEnd(ta.getText().length());
					}
					
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} 
				
			}
		});
		cc.add(bl,"North");
	}
	private static DecimalFormat df = null;  
	  
    static {  
        // 设置数字格式，保留一位有效小数  
        df = new DecimalFormat("#0.0");  
        df.setRoundingMode(RoundingMode.HALF_UP);  
        df.setMinimumFractionDigits(1);  
        df.setMaximumFractionDigits(1);  
    }  
	/** 
     * 格式化文件大小 
     * @param length 
     * @return 
     */  
    private String getFormatFileSize(long length) {  
        double size = ((double) length) / (1 << 30);  
        if(size >= 1) {  
            return df.format(size) + "GB";  
        }  
        size = ((double) length) / (1 << 20);  
        if(size >= 1) {  
            return df.format(size) + "MB";  
        }  
        size = ((double) length) / (1 << 10);  
        if(size >= 1) {  
            return df.format(size) + "KB";  
        }  
        return length + "B";  
    }  
	private void connect() {
		ta.append("尝试连接\n");
		try {
			socket = new Socket("127.0.0.1",8998);
			writer = new PrintWriter(socket.getOutputStream(),true);
			ta.append("完成连接\n");
			keyMap = new HashMap<Integer, String>(); 
			TestRsa.genKeyPair(keyMap);
			System.out.println("生成公钥和私钥："+keyMap.get(0)+" "+keyMap.get(1));
			writer.write(keyMap.get(0)+'\n');
			ta.append("生成并发送公钥\n");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	class Task implements Runnable {  
		  
        private Socket socket;  
        private DataInputStream dis;  
        private FileOutputStream fos;  
        public Task(Socket socket) {  
            this.socket = socket;  
        }  
        @Override  
        public void run() {  
            try {  
                dis = new DataInputStream(socket.getInputStream());  
  
                // 文件名和长度  
                ServicePublicKey = dis.readUTF();
                if (ServicePublicKey.equals("NotFount")) {
                	ta.append("无此文件"+'\n');
    				ta.setSelectionEnd(ta.getText().length());
    				return;
				}
                System.out.println("服务器公钥为："+ ServicePublicKey);
                String fileName = dis.readUTF();  
                long fileLength = dis.readLong();  
                File directory = new File("C:\\Socket\\download");  
                if(!directory.exists()) {  
                    directory.mkdir();  
                }  
                File file = new File(directory.getAbsolutePath() + File.separatorChar + fileName);  
                fos = new FileOutputStream(file);  
  
                // 开始接收文件  
                byte[] bytes = new byte[1024];  
                int length = 0;  
                System.out.println("开始接收");  
                while((length = dis.read(bytes, 0, bytes.length)) != -1) {  
                    fos.write(bytes, 0, length);  
                    fos.flush();  
                    if (file.length()==fileLength) {
						break;
					}
                }  
                if (fos!=null) {
					fos.close();
				}
                System.out.println("======== 文件接收成功 [File Name：" + fileName + "] [Size：" + getFormatFileSize(fileLength) + "] ========");
                ta.append("接收成功"+'\n');
				ta.setSelectionEnd(ta.getText().length());
            } catch (Exception e) {  
            	System.out.println("发生错误");
                e.printStackTrace();  
            }
        }  
    }  
	
	public static void main(String[] args) {
		MyClient client = new MyClient("向服务器送数据");
		client.setBounds(600,150,300,500);
		client.setVisible(true);
		client.connect();

	}

}
