package com.lab2.AndroidEncrypt;

import java.io.FileInputStream;
import org.apache.http.util.EncodingUtils;
import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class Showplaintext extends Activity{

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
        setContentView(R.layout.plaintext);
        
        final TextView Text = (TextView) findViewById(R.id.plaintext);
        final Button bPlain = (Button) findViewById(R.id.plain);
        final Button bEncript = (Button) findViewById(R.id.encript);
        final Button bDecript = (Button) findViewById(R.id.decript);
        
        bPlain.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Perform action on click
                String res=""; 
                
                try{ 
                 FileInputStream fin = openFileInput("plaintext.txt"); 
                 int length = fin.available(); 
                 byte [] buffer = new byte[length]; 
                 fin.read(buffer);     
                 res = EncodingUtils.getString(buffer, "UTF-8"); 
                 fin.close();     
                } 
                catch(Exception e){ 
                 e.printStackTrace(); 
                } 
                
                Text.setText(res);
            }
                
        });
        
        bEncript.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Perform action on click
                String res=""; 
                
                try{ 
                 FileInputStream fin = openFileInput("ciphertext.txt"); 
                 int length = fin.available(); 
                 byte [] buffer = new byte[length]; 
                 fin.read(buffer);     
                 res = EncodingUtils.getString(buffer, "UTF-8"); 
                 fin.close();     
                } 
                catch(Exception e){ 
                 e.printStackTrace(); 
                } 
                
                Text.setText(res);
            }
                
        });
        
        bDecript.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Perform action on click
                String res=""; 
                
                try{ 
                 FileInputStream fin = openFileInput("dephertext.txt"); 
                 int length = fin.available(); 
                 byte [] buffer = new byte[length]; 
                 fin.read(buffer);     
                 res = EncodingUtils.getString(buffer, "UTF-8"); 
                 fin.close();     
                } 
                catch(Exception e){ 
                 e.printStackTrace(); 
                } 
                
                Text.setText(res);
            }
                
        });
        		
	}
}
