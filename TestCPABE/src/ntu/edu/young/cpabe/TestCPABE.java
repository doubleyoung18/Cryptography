package ntu.edu.young.cpabe;

import java.lang.reflect.Proxy;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPow;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.FieldOver;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.jpbc.Point;
import it.unisa.dia.gas.jpbc.Polynomial;
import it.unisa.dia.gas.jpbc.PreProcessing;
import it.unisa.dia.gas.jpbc.Vector;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TestCPABE implements CPABEInterface{
	private String[] S = {"Patient", "Cardiologist Surgeon", "Anesthesiologist",
						  "Technician", "Cardiologist Hospital"};
	private String[] Sx = {"Patient", "Cardiologist Surgeon", "Anesthesiologist"};
	
	private Element P, Q, Pa, Pb, y,
					K, L;
	private Element[] H, Ki;
	private Element Kx, Lx;
	private Element[] Hx, Kix;
	private Field G1, G2, GT, Zr;
	private Pairing pairing;
	
	public TestCPABE()//初始化
	{
		pairing = PairingFactory.getPairing("f.properties");
		G1 = pairing.getG1();
		G2 = pairing.getG2();
		GT = pairing.getGT();
		Zr = pairing.getZr();
		P = G1.newRandomElement().getImmutable();
		Q = G2.newRandomElement().getImmutable();
	}
	
	/*
	 * Setup with attributes defined in G1
	 * Input:P∈G1 and Q∈G2, a set of attributes Attributes
	 * Output:Pubic Key PK(G1, G2, P, Q, Pb, y),{H1...Hn},Master private Key MK(Pa) 
	 */
	public void Setup()
	{
		System.out.println("-----------------系统建立阶段--------------------");
		Element a = Zr.newRandomElement(), 
				b = Zr.newRandomElement();//1.Choose at random:a and b ∈ Zr 
		Pa = P.mulZn(a);//2.Pa←[a]P {Scalar mult. in G1}
		Pb = P.mulZn(b);//3.Pb←[b]P {Scalar mult. in G1}
		y = pairing.pairing(P, Q).powZn(a);//4.y←e(P, Q)^a {single pairing, exp in GT}
		
		H = new Element[S.length];
		for (int i = 0; i < S.length; i++)//5.for i←1 to #H do
		{
			H[i] = G1.newElement().setFromHash(S[i].getBytes(), 0, S[i].length());
			//6.Generate a point H[i]∈ G1 {H1(.) application}
		}//7.end for
		
		System.out.println("Public Key PK=(G1,G2,P,Q,Pb,y),{H1,...,Hn}");//8.PK←(G1, G2, P, Q, Pb, y),{H1...Hn}
		System.out.println("P:" + P + '\n'
					   + "Q:" + Q + '\n'
					   + "Pb:" + Pb + '\n'
					   + "y:" + y + '\n');
		for (int i = 0; i < S.length; i++)
			System.out.println("H" + (i+1) + ":" + H[i]);
		System.out.println("\nMaster private Key MK=(Pa)");//9.MK←(Pa)
		System.out.println("Pa:" + Pa);
		//10.return PK, MK
	}
	
	/*
	 * Encryption with attributes defined in G1 
	 * Input:A message M, PK, an access structure S given as a u*t LSSS Matrix and I{1,2,...,u} as I={i:ρ(i)∈H}
	 * Output:Ciphertext CT={S,C,Cd,(C1,D1),...,(Cu,Du)}
	 */
	public void Encryption()
	{
		System.out.println("-------------------加密阶段----------------------");
	}
	
	/*
	 * KeyGeneration with attributes defined in G1
	 * Input:MK and a set of user's attributes H
	 * Output:A private key SK={K,L,K1,...,KvH}
	 */
	public void KeyGeneration()
	{
		System.out.println("-----------------密钥生成阶段--------------------");
		Element r = Zr.newRandomElement();//1.Choose at random r∈Zr;
		K = Pa.add(Pb.mulZn(r));//2.K←Pa+[r]Pb {Scalar mult., point add in G1}
		L = Q.mulZn(r);//3.L←[r]Q {Scalar mult. in G2}	
		
		Ki = new Element[H.length];
		for(int i = 0; i < H.length; i++)//4.for i=1 to vH do 
		{
			Ki[i] = G1.newElement();
			Ki[i] = H[i].mulZn(r);//5.Ki←[r]Hi {Scalar mult. in G1}
		}//6.end for
			
		System.out.println("private key SK={K,L,K1,...,KvH}");//7.Sk←{K,L,K1,...,KvH}
		System.out.println("K:" + K + '\n'
						 + "L:" + L + '\n');
		for (int i = 0; i < H.length; i++)
			System.out.println("K" + (i+1) + ":" + Ki[i]);
		//8.return SK
	}
	
	/*
	 * Decryption with attributes defined in G1
	 * Input:CT and its LSSS matrix S, SK and its set of attributes H
	 * Output:Plaintext M(if the attributes in SK satisfy the ciphertext's policy)
	 */
	public void Decrytion()
	{
		System.out.println("-------------------解密阶段----------------------");
	}
	
	/* 
	 * Delegate with parameters in G1
	 * Input:SK and a subset Hx of attributes corresponding to a user
	 * Output:A private key SKx={Kx,Lx,Kx1,...KxvHx}
	 */
	public void Delegate()
	{
		System.out.println("-------------------委派阶段----------------------");
		Element rx = Zr.newRandomElement();//1.Choose at random:rx∈Zr
		Kx = K.add(Pb.mulZn(rx));//2.Kx←K+[rx]Pb {Scalar mult., point add. in G1}
		Lx = L.add(Q.mulZn(rx));//3.Lx←L+[rx]Q {Scalar mult., point add. in G2}	
		
		Hx = new Element[Sx.length];
		Kix = new Element[Sx.length];
		for(int i = 0; i < Sx.length; i++)//4.for i=1 to vHx do
		{
			Hx[i] = G1.newElement().setFromHash(Sx[i].getBytes(), 0, Sx[i].length());
			Kix[i] = G1.newElement();
			Kix[i] = Ki[i].add(Hx[i].mulZn(rx));//5.Kix[i]←Ki[i]+[rx]Hx[i] {Scalar mult. point add. in G1}
		}//6.end for
			
		System.out.println("private key SKx={Kx,Lx,Kx1,...,KxvHx}");//7.Skx←{Kx,Lx,Kx1,...,KxvHx}
		System.out.println("Kx:" + Kx + '\n'
				 		 + "Lx:" + Lx + '\n');
		for (int i = 0; i < Hx.length; i++)
			System.out.println("Kx" + (i+1) + ":" + Kix[i]);
		//8.return SKx
	}
	
	public static void main(String[] args)
	{
		TestCPABE abe = new  TestCPABE();	
		CPABEInterface CPABEProxy = (CPABEInterface) Proxy.newProxyInstance(
				 TestCPABE.class.getClassLoader(),
				 new Class[] { CPABEInterface.class }, 
				 new TimeCountProxyHandle(abe)
				 );
		CPABEProxy.Setup();
		CPABEProxy.Encryption();
		CPABEProxy.KeyGeneration();
		CPABEProxy.Decrytion();
		CPABEProxy.Delegate();	
	}
}
