

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Wrap {
	private final Key CipherKey;
	private final byte[] KeytoCipher;
	private static byte[] ICV2 = {(byte)0x6a,(byte)0x59,(byte)0x59,(byte)0x6a};
	private byte[] IV;
	public Wrap(byte[] key1,Key key2,byte[] IV) {
		// TODO Auto-generated constructor stub
		this.KeytoCipher = key1;
		this.CipherKey = key2;
		this.IV = IV;
//		for(int i=0;i<CipherKey.getEncoded().length;i++)
//		{
//			System.out.print(CipherKey.getEncoded()[i] + " ");
//		}
		
	}

	private int caculatePadlen()
	{
		byte[] keyByte = KeytoCipher;
		double len = (double)keyByte.length;
	
		int result =  (int)  ( (8*Math.ceil(len/8)) - (keyByte.length*8)/8);
		
		return result;
	}

	private byte[] constuctPadArray(int padLen){
		byte[] padArray = new byte[padLen];
		
		return padArray;
	}
	private byte[] constructS(byte[] padArray){
		byte[] KeyArray = KeytoCipher;
		int len = KeyArray.length;
		byte[] lenArray = new byte[4];
		lenArray[0] = (byte)((len >> 0)  & 0xff);
		lenArray[1] = (byte)((len >> 8)  & 0xff);
		lenArray[2] = (byte)((len >> 16) & 0xff);
		lenArray[3] = (byte)((len >> 24) & 0xff);
		byte[] S = new byte[lenArray.length + ICV2.length + KeyArray.length + padArray.length];
		System.arraycopy(ICV2, 0, S, 0, ICV2.length);
		System.arraycopy(lenArray, 0, S, ICV2.length, lenArray.length);
		System.arraycopy(KeyArray, 0, S, ICV2.length+lenArray.length, KeyArray.length);
		System.arraycopy(padArray, 0, S, ICV2.length+lenArray.length+KeyArray.length, padArray.length);
//		
//		for(int i=0;i<S.length;i++){
//			if(i%8 ==0)
//				System.out.println();
//			System.out.print(S[i]+" ");
//		}
		return S;
	}
	public byte[] doWrap(){
		
		int padLen = this.caculatePadlen();
		byte[] PadArray = this.constuctPadArray(padLen);
		byte[] S = this.constructS(PadArray);
		
		byte[][] Sn = new byte[S.length/8][8];
		byte[][] An = new byte[S.length/8][8];
		byte[][] R0i = new byte[S.length/8][8];
		//cut S into Sn with length of 8 bytes 
		for(int i = 0;i<S.length/8;i++)
		{
			System.arraycopy(S, i*8, Sn[i], 0, 8);
//			for(int j = 0; j < 8; j++)
//			{	
//				Sn[i][j] = S[8*i+j];
//			}
		}
		//A0 = S1
		System.arraycopy(Sn[0], 0, An[0], 0, 8);
//		An[0] = Sn[0];
		//let s=6(n-1)
		int s = 6*(S.length/8-1);
		int n = S.length/8;
		System.out.println("n is " + n);
		//for i=2,3.......n, let R0(i) = S(i)
		byte[][] returnR = new byte[s][8];
		byte[][] Rnt = new byte[s][8];
		for(int i = 1;i < Sn.length;i++)
		{
			System.arraycopy(Sn[i], 0, R0i[i], 0, 8);
			//R0i[i] = Sn[i];
		}	
		byte[] currentA = new byte[8];
		byte[] currentR = new byte[8];
		byte[] currentA_R = new byte[16];
		//init A(0) to current A
		System.arraycopy(An[0], 0, currentA, 0, 8);
//		for(int i=0;i<8;i++)
//		{
//			
//			currentA[i] = An[0][i];
//		}
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(IV);
		// step2,  i is t
		//******
		for(int i=0; i<(s);i++){

			// I do not know why the array copy can not apply to a two dimension array.
			// so i use loop
			//R2(t-1) = R(2+t-1)(0)
			if(i < (n-1)){
//				for(int j=0;j<8;j++){
//					currentR[j] = R0i[2+i-1][j];
//					}
				System.arraycopy(R0i[2+i-1], 0, currentR, 0, 8);
			}else if(i >= (n-1)){
				System.arraycopy(returnR[i-n+1], 0, currentR, 0, 8);
			}
			
//			System.arraycopy(R0i[2+i-1], 0, currentR, 0, 8);
			//Concatenate A(t-1) with R2(t-1)
			System.arraycopy(currentA, 0, currentA_R, 0, 8);
			System.arraycopy(currentR, 0, currentA_R, 8, 8);
			//init cipher
			
			try{
				
				Cipher ecipher = Cipher.getInstance("AES/CBC/NoPadding");
				ecipher.init(Cipher.ENCRYPT_MODE, this.CipherKey, paramSpec);
	
				try {
					
					currentA_R = ecipher.doFinal(currentA_R);
					
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
//				System.out.println("*"+currentA_R);
				
			}
			catch (InvalidAlgorithmParameterException e) {
			     } catch (NoSuchPaddingException e) {
			     } catch (NoSuchAlgorithmException e) {
			     } catch (InvalidKeyException e) {
			     }
			// get MSB and LSB
			System.arraycopy(currentA_R, 0, currentA, 0, 8);
			System.arraycopy(currentA_R, 8, currentR, 0, 8);
//			System.out.println();
//			System.out.print("currentA");
//			for(int j =0;j<8;j++){
//				System.out.print(  currentA[j] + " ");
//			}
//			System.out.print("currentR");
//			for(int j =0;j<8;j++){
//				
//				System.out.print(  currentR[j] + " ");
//			}
//			System.out.print("currentA_R");
//			for(int j =0;j<16;j++){
//				
//				System.out.print(  currentA_R[j] + " ");
//			}
			

			// XOR MSB with [t]64
			byte[] t64 = intTo64Byte((i+1));

			for(int j=0;j<8;j++){
				// have not confirm this, may be have some problems
				currentA[j] = (byte)(currentA[j]^t64[j]);
			}
			System.arraycopy(currentR, 0, returnR[i], 0, 8);
			
		}
//		System.out.println("currentR");
//		for(int i=0;i<currentR.length;i++){
//			System.out.print(currentR[i] + " ");
//		}
		byte[][] Rsi = new byte[n][8];
		for(int i=1;i<n;i++){
			System.arraycopy(returnR[s-n+i], 0, Rsi[i], 0, 8);
		}
		System.arraycopy(currentA, 0, Rsi[0], 0, 8);
//		System.out.println("currentAS");
//		for(int i =0;i<currentA.length;i++){
//			System.out.print(currentA[i] + " ");
//		}
		byte[] RSI = new byte[n*8];
		for(int i = 0; i<n;i++){
			System.arraycopy(Rsi[i], 0, RSI, i*8, 8);
		}
		return RSI;
	}
	private byte[] intTo64Byte(int i){
		byte[] Byte64 = new byte[8];
		Byte64[0] = (byte)((i >> 0)  & 0xff);
		Byte64[1] = (byte)((i >> 8)  & 0xff);
		Byte64[2] = (byte)((i >> 16) & 0xff);
		Byte64[3] = (byte)((i >> 24) & 0xff);
		Byte64[4] = (byte)((i >> 32) & 0xff);
		Byte64[5] = (byte)((i >> 40) & 0xff);
		Byte64[6] = (byte)((i >> 48) & 0xff);
		Byte64[7] = (byte)((i >> 56) & 0xff);
		return Byte64;
	}
	public static  int makeInt(byte b3,byte b2, byte b1, byte b0){
		   
		   return (int)((((b3 & 0xff)<<24 | ((b2&0xff)<<16) | ((b1&0xff)<<8) | ((b0&0xff)<<0))));
	   }
	/*
	public static void main(String[] args) throws NoSuchAlgorithmException
	{
//		byte[] padArray = new byte[8*2];
//		byte[][] a = new byte[24][24];
//		for(int i=0;i<24;i++){
//			a[0][i]=1;
//		}
//		byte[] b = new byte[24];
//		System.arraycopy(a[0], 0, b, 0, 24);
//		for(int i=0;i<b.length;i++)
//		{
//			System.out.print(b[i] + " ");
//		}
		
		KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
		byte[] key1 = new byte[49];
		for(int i = 0; i<key1.length;i++){
			key1[i] = 0x10;
		}
		key1[7] = 0x11;
		key1[10]=0x00;
		
		Key key2 = keygenerator.generateKey();
		Wrap wrap = new Wrap(key1,key2);
		int padLen = wrap.caculatePadlen();
		byte[] PadArray = wrap.constuctPadArray(padLen);
		byte[] S = wrap.constructS(PadArray);
		byte[] IV =
				{		
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09,0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
				};
		
		byte[] result = wrap.doWrap(S, IV);

		

		unWrap unwrap = new unWrap(result,key2,IV);
		byte[] a = unwrap.doUnWrap();
		System.out.println("original Key1");
		for(int i=0;i<key1.length;i++){
			System.out.print( key1[i] + " ");
		}
		System.out.println("unwrap Key1");
		for(int i=0;i<a.length;i++){
			System.out.print( a[i] + " ");
		}

		
		
	}*/
	
}
