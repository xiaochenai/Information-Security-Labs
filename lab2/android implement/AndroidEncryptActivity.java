package com.lab2.AndroidEncrypt;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;


public class AndroidEncryptActivity extends Activity {
    /** Called when the activity is first created. */
    @Override
    
    public void onCreate(Bundle savedInstanceState) {	
    	super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        

        
        final Button button1 = (Button) findViewById(R.id.button1);
        final EditText alg = (EditText) findViewById(R.id.EditText01);
        final EditText mod = (EditText) findViewById(R.id.EditText02);
        final EditText key = (EditText) findViewById(R.id.EditText03);
        
        button1.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Perform action on click
                String salgorithm;
                String smode;
                String skey;
            	
                salgorithm = alg.getText().toString();
            	smode = mod.getText().toString();
            	skey = key.getText().toString();
            	
            	try {
					FileInputStream fclear = openFileInput("plaintext.txt");
	            	FileOutputStream fcipher =openFileOutput("ciphertext.txt", MODE_PRIVATE);
	            	CipherFile cf = new CipherFile(salgorithm, smode, skey);
	            	cf.encrypt(fclear, fcipher);
	            	
	            	FileInputStream fciphered = openFileInput("ciphertext.txt");
	            	FileOutputStream fedcipher =openFileOutput("dephertext.txt", MODE_PRIVATE);
	            	cf.decrypt(fciphered, fedcipher);
	            	
				} catch (Exception e) {
				}finally{
					Intent secondPage = new Intent("android.intent.action.SHOWPLAINTEXT");
					startActivity(secondPage);
				}
            	
            	
         	
            }
        });
    }
    
}


