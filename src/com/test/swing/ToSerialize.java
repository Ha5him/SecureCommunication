package com.test.swing;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.test.rsa.TestDes;

public class ToSerialize {

	/**
	 * <p>
	 * ClassName: TestObjSerializeAndDeserialize
	 * <p>
	 * <p>
	 * Description: 测试对象的序列化和反序列
	 * <p>
	 * 
	 * @author xudp
	 * @version 1.0 V
	 * @createTime 2014-6-9 下午03:17:25
	 */

	public static void main(String[] args) throws Exception {
		TestDes td = new TestDes("sadf");
		System.out.println(td.getKey());
		td.encrypt("C:\\Socket\\Afile.txt", "C:\\Socket\\Afile.txt.DES"); // 加密
		SerializePerson(td.getKey(),"C:\\Socket\\key.key");// 序列化Person对象
		
		Key p = DeserializePerson("C:\\Socket\\key.key");// 反序列Perons对象
		TestDes dd = new TestDes("sadf");
		//dd.setKey(p);
		dd.decrypt("C:\\Socket\\Afile.txt.DES", "C:\\Socket\\Afile.txt.DES.txt"); // 解密
		System.out.println(p);
		
		SerializeString("abc", "C:\\Socket\\abc.txt");
		System.out.println(DeserializeString("C:\\Socket\\abc.txt"));
	}

	/**
	 * MethodName: SerializePerson Description: 序列化Person对象
	 * 
	 * @author xudp
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public static void SerializePerson(Key key,String fileName) throws FileNotFoundException, IOException {
		// ObjectOutputStream 对象输出流，将Person对象存储到E盘的Person.txt文件中，完成对Person对象的序列化操作
		ObjectOutputStream oo = new ObjectOutputStream(new FileOutputStream(new File(fileName)));
		oo.writeObject(key);
		System.out.println("Key对象序列化成功！");
		oo.close();
	}

	/**
	 * MethodName: DeserializePerson Description: 反序列Perons对象
	 * 
	 * @author xudp
	 * @return
	 * @throws Exception
	 * @throws IOException
	 */
	public static Key DeserializePerson(String fileName) throws Exception, IOException {
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(fileName)));
		Key key = (Key) ois.readObject();
		System.out.println("Key对象反序列化成功！");
		return key;
	}
	
	public static void SerializeString(String key,String fileName) throws FileNotFoundException, IOException {
		// ObjectOutputStream 对象输出流，将Person对象存储到E盘的Person.txt文件中，完成对Person对象的序列化操作
		ObjectOutputStream oo = new ObjectOutputStream(new FileOutputStream(new File(fileName)));
		oo.writeObject(key);
		System.out.println("String对象序列化成功！");
		oo.close();
	}

	/**
	 * MethodName: DeserializePerson Description: 反序列Perons对象
	 * 
	 * @author xudp
	 * @return
	 * @throws Exception
	 * @throws IOException
	 */
	public static String DeserializeString(String fileName) throws Exception, IOException {
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(fileName)));
		String key = (String) ois.readObject();
		System.out.println("String对象反序列化成功！");
		return key;
	}

}
