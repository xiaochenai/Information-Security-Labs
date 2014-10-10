import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import biz.source_code.base64Coder.Base64Coder;


public class keyDeriveFunction {
	
	private byte[] Psw;
	private byte[] Salt;
	private int C;
	private int kLen;
	private int hLen = 512;
	private byte[][] T;
	private byte[] MK;
	

	public keyDeriveFunction(byte[] Psw, byte[] Salt, int C, int kLen){
		this.Psw = Psw;
		this.Salt = Salt;
		this.C = C;
		this.kLen = kLen;
		

	}
	public void DeriveMK() throws NoSuchAlgorithmException, InvalidKeyException{
		// len is in bit
		int len = 0;
		if(kLen % hLen == 0)
			len = kLen/hLen;
		else
			len = kLen/hLen + 1;
		System.out.println("LEN  " + len);
		SecretKey secretekey = new SecretKeySpec(Psw,"HmacSHA512");
		Mac mac = Mac.getInstance(secretekey.getAlgorithm());
		mac.init(secretekey);
		// r is in bit
		int r = (kLen - (len - 1) * hLen);
		System.out.println("IIII : " + r);
		T = new byte[len][64];
		byte[] U0 = new byte[Salt.length + 4];
	
		byte[][] U = new byte[C][64];
		byte[] current = new byte[64];
		for(int i = 0; i < len; i++){
			System.arraycopy(Salt, 0, U0, 0, Salt.length);
			byte[] byteArray = IntToByte(i);
			System.arraycopy(byteArray, 0, U0, Salt.length, 4);
			for(int j = 0; j < C; j++){
				if(j == 0){
					System.arraycopy(mac.doFinal(U0), 0, U[j], 0, U[j].length);
				//	System.out.println("MAC  " + Base64Coder.encodeLines(mac.doFinal(U0)));
				}
					
				else{
					System.arraycopy(mac.doFinal(U[j-1]), 0, U[j], 0, U[j].length);
				//	System.out.println("MAC  " + Base64Coder.encodeLines(mac.doFinal((U[j-1]))));
				}
					
				byte a;
				byte b;
				for(int p = 0; p < current.length;p++){
					 a =T[i][p];
					 b =U[j][p];
					 current[p] = (byte) (a ^ b);
				}
				System.arraycopy(current, 0, T[i], 0, current.length);
			}
		}
		
		MK = new byte[64*(len-1) + r/8];
		System.out.println("MK LENGTH : " + MK.length);
		for(int i = 0;i<(len-1);i++){
			System.arraycopy(T[i], 0, MK, 64*i, 64);
		}
		System.arraycopy(T[len-1], 0, MK, 64*(len-1), r/8);
		
	}
	private byte[] IntToByte(int i){
		byte[] byteArray = new byte[4];
		byteArray[0] = (byte)((i >> 0)  & 0xff);
		byteArray[1] = (byte)((i >> 8)  & 0xff);
		byteArray[2] = (byte)((i >> 16) & 0xff);
		byteArray[3] = (byte)((i >> 24) & 0xff);
		return byteArray;
	}
	public byte[] GetMK(){
		return MK;
	}
	

}
