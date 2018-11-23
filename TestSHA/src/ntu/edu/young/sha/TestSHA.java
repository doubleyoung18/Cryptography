package ntu.edu.young.sha;

import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class TestSHA {
	public static String SHAEncrypt(String orignal, String algorithm) { 
		MessageDigest md = null; 
		try { 
			md = MessageDigest.getInstance(algorithm);//创建使用ALGORITHM的信息摘要 
		} catch (NoSuchAlgorithmException e) { 
			e.printStackTrace(); 
		} 
		if (md != null) { 
			byte[] origBytes = orignal.getBytes();//获取原报文
			md.update(origBytes);//使用原报文更新摘要 
			byte[] digestRes = md.digest();//利用填充进行Hash计算 
			String digestStr =  ByteToString(digestRes);//获取计算后的摘要 
			return digestStr; 
			//return digestRes;
		}
		return null; 
	}
	
	private static String ByteToString(byte[] byt) {//byte[]转化为十六进制String
		String str = "";
		String tmp = null;
		for (int i = 0; i < byt.length; i++)
		{
			tmp = (Integer.toHexString(byt[i] & 0xFF));
			if (tmp.length() == 1) 
			{
				str += "0";
			}
			str += tmp;
		}
		return str;
	}
	
	public static void main(String[] args)
	{
		Scanner in = new Scanner(System.in);
		String m = in.nextLine();
		in.close();
		String algorithm = "SHA-256";//SHA-1，SHA-224，SHA-256，SHA-384，和SHA-512
		String c = SHAEncrypt(m, algorithm);
		System.out.println(c);
		System.out.println(m.length() + " " + c.length());
	}
}