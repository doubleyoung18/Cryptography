package ntu.edu.young.basicident;

import java.math.*;
import java.util.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.lang.reflect.Proxy;

public class TestBasicIdent implements BasicIdentInterface {

	private Element s, r, P, Ppub, Su, Qu, V, T1, T2, T3, W;
	//s主密钥,r随机化参数r∈Zr,P为G1生成元,Ppub=sP,Qu公钥,Su私钥,V=rP,T1=e(Ppub,Qu)^r,T2=e(V,Su),T3=T2^-1;
	private int lm;//lm消息的字节长度
	private Element m;//明文m
	private Field G1, Zr, GT, G2;//G1循环加法群,Zr整数环
	private Pairing pairing;
	
	public TestBasicIdent() {
		init();
	}

	/**
	 * 初始化
	 */
	private void init() {
		pairing = PairingFactory.getPairing("a.properties");//
		PairingFactory.getInstance().setUsePBCWhenPossible(true);
		checkSymmetric(pairing);
		// 将变量r初始化为Zr中的元素
		Zr = pairing.getZr();// 指数群
		r = Zr.newElement();
		//将变量Ppub，Qu，Su，V初始化为G1中的元素，G1是循环加法群
		G1 = pairing.getG1();
		Ppub = G1.newElement();
		Qu = G1.newElement();
		Su = G1.newElement();
		V = G1.newElement();
		//将变量T1，T2初始化为GT中的元素，GT是循环乘法群
		Field GT = pairing.getGT();
		G2 = GT;
		T1 = GT.newElement();
		T2 = GT.newElement();

	}

	/**
	 * 判断配对是否为对称配对，不对称则输出错误信息
	 * 
	 * @param pairing
	 */
	private void checkSymmetric(Pairing pairing) {
		if (!pairing.isSymmetric()) {
			throw new RuntimeException("不是对称双线性群");
		}
	}

	@Override
	public void buildSystem() {
		System.out.print("-------------------系统建立阶段----------------------\n"
				+ "公开:\n系统参数{G1,GT,lm,p,e,P,Ppub,H1}:\n");
		s = Zr.newRandomElement().getImmutable();// //随机生成主密钥s
		P = G1.newRandomElement().getImmutable();// 生成G1的生成元P
		Ppub = P.mulZn(s);// 计算Ppub=sP,注意顺序
		System.out.println("明文字节数lm=" + 128);
		System.out.println("G1生成元P=" + P);
		System.out.println("Ppub=" + Ppub + "\n");
		System.out.println("保密:");
		System.out.println("主密钥s=" + s);
	}

	@Override
	public void extractSecretKey() {
		System.out.println("-------------------密钥提取阶段----------------------");
		Qu = pairing.getG1().newElement().setFromHash("IDu".getBytes(), 0, 3)
				.getImmutable();//从长度为3的Hash值IDu确定用户U产生的公钥Qu，双线性群里获得一个元素
		Su = Qu.mulZn(s).getImmutable();//计算Su=sQu
		System.out.println("公钥Qu=" + Qu);//用户的公钥
		System.out.println("私钥Su=" + Su);//用户的私钥
	}

	@Override
	public void encrypt() {
		System.out.println("-------------------加密阶段----------------------");
		m = G2.newRandomElement();
		lm = m.getLengthInBytes();
		System.out.println("明文m" + m);
		r = Zr.newRandomElement().getImmutable();
		V = P.mulZn(r);//计算V=rP
		T1 = pairing.pairing(Ppub, Qu).getImmutable();// 计算T1=e(Ppub,Qu)=e(sP,Qu)
		T1 = T1.powZn(r).getImmutable();// 对结果随机化T1=e(Ppub,Qu)^r=e(sP,Qu)^r
		W = T1.mul(m);
		
		/*
		byte[] bytm = m.toBytes();
		byte[] bytT1 = T1.toBytes();
		byte[] H2 = SHAEncrypt(ByteToString(bytT1), "SHA-256");
		byte[] bytW;
		System.out.println(bytm.length + " " + bytT1.length + " " + H2.length);
		System.out.println(ByteToString(H2));
		*/
		
		
		System.out.println("加密后的密文c(V,W)=(" + V + "," + W + ")\n");
		System.out.println("相应参数:");
		System.out.println("随机化参数r=" + r);
		System.out.println("V=rP" + V);
		System.out.println("T1=e（Ppub,Qu）^r=" + T1);
		System.out.println("W=mT1=" + W);
	}

	@Override
	public void decrypt() {
		System.out.println("-------------------解密阶段----------------------");
		T2 = pairing.pairing(V, Su).getImmutable();//计算T2=e(V,Su)=e(rP,sQu)
		T3 = T2.invert();//计算T2的逆元T3
		System.out.println("解密后的明文m=W*T2-1" + T3.mul(W) + "\n");	
		System.out.println("相应参数:");
		System.out.println("T2=e(V,Su)=" + T2);
		System.out.println("T2^-1=e(V,Su)=" + T3);
		int byt = V.getLengthInBytes();// 求V的字节长度，假设消息长度为128字节
		System.out.println("密文长度" + (byt + lm));
	}

	public static void main(String[] args) {
		TestBasicIdent ident = new TestBasicIdent();
		// 动态代理，统计各个方法耗时
		BasicIdentInterface identProxy = (BasicIdentInterface) Proxy.newProxyInstance(
										 TestBasicIdent.class.getClassLoader(),
										 new Class[] { BasicIdentInterface.class }, 
										 new TimeCountProxyHandle(ident)
										 );

		identProxy.buildSystem();
		identProxy.extractSecretKey();
		identProxy.encrypt();
		identProxy.decrypt();
	}
}