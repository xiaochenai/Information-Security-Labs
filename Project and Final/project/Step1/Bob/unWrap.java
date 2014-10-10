

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class unWrap {
	private final Key CipherKey;
	private final byte[] encryptedKey;
	private static byte[] ICV2 = {(byte)0x6a,(byte)0x59,(byte)0x59,(byte)0x6a};
	private int N=0;
	private byte[] IV;
	
	public unWrap(byte[] cipherText,Key key, byte[] IV){
		this.CipherKey = key;
		this.encryptedKey = cipherText;
		N = encryptedKey.length/8;
//		System.out.println("KEY");
//		for(int i=0;i<CipherKey.getEncoded().length;i++)
//		{
//			System.out.print(CipherKey.getEncoded()[i] + " ");
//		}
		this.IV = IV;
	}
	public byte[] doUnWrap(){

		byte[] S;
		int s = 6*(N-1);
		byte[][] Cn = new byte[N][8];
		byte[][] An = new byte[N][8];
		byte[][] Rsi = new byte[N][8];
		// cut C into 8bytes array Cn
		for(int i = 0; i < N; i++){
			System.arraycopy(encryptedKey, i*8, Cn[i], 0, 8);
		}
		byte[] currentA = new byte[8];
		byte[] currentR = new byte[8];
		byte[] currentA_R = new byte[16];
		byte[][] R2 = new byte[s][8];
		
		//A(s) = C(1)
		System.arraycopy(Cn[0], 0, currentA, 0, 8);
//		System.out.println("currentAS");
//		for(int i =0;i<currentA.length;i++){
//			System.out.print(currentA[i]+ " ");
//		}
		//R(s)(i) = C(i) i=2 -----> i=N
		for(int i = 1;i<N;i++){
			System.arraycopy(Cn[i], 0, Rsi[i], 0, 8);
		}
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(IV);

		// i is t
		for(int i = s-1; i>-1;i--){
			byte[] t64 = intTo64Byte(i+1);
			
			//concatenate A(t) with t[64]
			for(int j = 0;j < 8;j++){
				currentA[j] = (byte)(currentA[j]^t64[j]);
			}
			
			//Rsi[N-1]----->Rsi[1]
			if(i >= (s-N+1)){
				System.arraycopy(Rsi[i+N-s], 0, currentR, 0, 8);
			}else if(i <= (s-N)){
				//R2[N-1]<--------R2[S-1]
				System.arraycopy(R2[i+N-1], 0, currentR, 0, 8);
			}
//			System.out.println("CURRENTR@@@@");
//			for(int j=0;j<currentR.length;j++){
//				System.out.print(currentR[j] + " ");
//			}
//			//concatenate A(t) with Rn(t)
			System.arraycopy(currentA, 0, currentA_R, 0, 8);
			System.arraycopy(currentR, 0, currentA_R, 8, 8);
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
			
			try{
				
				Cipher ecipher = Cipher.getInstance("AES/CBC/NoPadding");
				ecipher.init(Cipher.DECRYPT_MODE, this.CipherKey, paramSpec);
				try {
//					System.out.println("currentA_R length " + currentA_R.length);
//					for(int j =0;j<currentA_R.length;j++){
//						System.out.print(currentA_R[j] + " ");
//					}
//					System.out.println("**"+currentA_R);
					//System.out.println("&"+currentA_R);
					currentA_R = ecipher.doFinal(currentA_R);
					System.out.println("cc");
//					System.out.println("^*&^*(&^(*&^(&*");
				} catch(Exception e){
					System.out.println("error");
				}
//				catch (IllegalBlockSizeException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (BadPaddingException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//				System.out.println("####");

			}catch(Exception e){}
//			catch (InvalidAlgorithmParameterException e) {
//		     } catch (NoSuchPaddingException e) {
//		     } catch (NoSuchAlgorithmException e) {
//		     } catch (InvalidKeyException e) {
//		     }
			
//			for(int j=0;j<currentA_R.length;j++){
//				
//				System.out.print(currentA_R[j]+" ");
//			}
			System.arraycopy(currentA_R, 0, currentA, 0, 8);
			System.arraycopy(currentA_R, 8, R2[i], 0, 8);
		}
		byte[] returnR = new byte[N*8];
		System.arraycopy(currentA, 0, returnR, 0, 8);
		for(int i=1; i<N;i++){
			//R2[0]----->R2[N-2]
			System.arraycopy(R2[i-1], 0, returnR, i*8, 8);
		}
		for(int i=0;i<returnR.length;i++){
			if(i%8 ==0)
				System.out.println();
			System.out.print(returnR[i]+" ");
		}
		
		byte[] Icv2 = new byte[4];
		System.arraycopy(returnR, 0, Icv2, 0, 4);
		if(compareICV2(Icv2))
			System.out.println("Finish ICV2 compare " );
		else
			System.out.println("ICV2 compare FAIL");
		byte[] Plen = new byte[4];
		System.arraycopy(returnR, 4, Plen, 0, 4);
		int plen = makeInt(Plen[3],Plen[2],Plen[1],Plen[0]);
		System.out.println(plen);
		int padlen = 8*(N-1)-plen;
		
		if(padlen<0 || padlen>7)
			System.out.println(" padlen test FAIL");
		else
			System.out.println("padlen past test");
		System.out.println("PADLEN : " + padlen);
		byte[] pad = new byte[padlen];
		System.arraycopy(returnR, returnR.length-padlen, pad, 0, padlen);
		System.out.println("&&&");
		for(int i=0;i<padlen;i++){
			System.out.print(pad[i] + " ");
		}
		if(testPadArray(pad))
			System.out.println("pass pad test");
		else
			System.out.println("FAIL pad test");
		
		byte[] returnD = new byte[plen];
		byte[] current = new byte[8*(N-1)];
		System.arraycopy(returnR, 8, current, 0, 8*(N-1));
		System.arraycopy(current, 0, returnD, 0, plen);
		return returnD;
	}   
	private  int makeInt(byte b3,byte b2, byte b1, byte b0){
		   
		   return (int)((((b3 & 0xff)<<24 | ((b2&0xff)<<16) | ((b1&0xff)<<8) | ((b0&0xff)<<0))));
	   }
	private boolean testPadArray(byte[] PadArray){
		boolean result = true;
		for(int i=0;i<PadArray.length;i++){
			if(PadArray[i] != 0)
				result =false;
		}
		return result;
	}
	private boolean compareICV2(byte[] Icv2){
		boolean result = true;
		for(int i=0;i<4;i++){
			if(Icv2[i] != ICV2[i])
				result = false;
		}
		return result;
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
}
