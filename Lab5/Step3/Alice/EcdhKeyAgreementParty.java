/*
 * Copyright (c) 2009, RSA, The Security Division of EMC.
 *
 * This file is used to demonstrate how to interface to an RSA
 * Security licensed development product.  You have a
 * royalty-free right to use, modify, reproduce and distribute this
 * demonstration file (including any modified version), provided that
 * you agree that RSA Security has no warranty, implied or
 * otherwise, or liability for this demonstration file or any modified
 * version.
 *
 */


import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.ECKey;
import com.rsa.jsafe.provider.GCMParameterSpec;

/**
 * Represents a single entity in the key agreement. In a real multi-party
 * key agreement this party would be on a separate computer to the
 * other parties in the key agreement.
 */
public final class EcdhKeyAgreementParty {
    // The plaintext sent from one party to the other parties.
    private static final byte[] PLAINTEXT = new byte[] {
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
    };

    // Key agreement algorithm to use. To change from using ECDH to using DH,
    // a javax.crypto.spec.DHParameterSpec would need to be used in the code below
    // rather than a java.security.spec.ECGenParameterSpec
    private static final String ECDH = "ECDH";

    // Symmetric algorithm to use.
    private static final String AES = "AES";

    // To simplify the example, the JCE provider is used directly, rather
    // than registering the provider.
    private static final java.security.Provider JCE = new com.rsa.jsafe.provider.JsafeJCE();

    // To minimize the amount of entropy that needs to be gathered as part of the
    // self-seeding process, use one PRNG globally.
    private static final SecureRandom RAND = createRandom();
    private static SecureRandom createRandom() {
        try {
            return SecureRandom.getInstance("ECDRBG", JCE);
        } catch (Exception e) {
            throw new RuntimeException("Unexpectedly ECDRBG not supported");
        }
    }

    // Name of the key agreement party. This is used to differentiate the
    // debug output.
    private String partyName;

    // ECDH key pair.
    private KeyPair keyPair;

    // KeyAgreement object holds the current state of the key agreement
    // process.
    private KeyAgreement keyAgree;

    // KeyFactory is used to convert arrays of bytes to public key objects.
    private KeyFactory keyFactory;

    // AES key which is generated from the shared secret.
    private SecretKey sharedSecretKey;


    /**
     * Creates a party to a shared secret.
     *
     * @param party The name of the party of the shared secret.
     * @param agreedParameters Parameters previously agreed between parties
     *  of the key agreement.
     * @throws Exception if unexpectedly the ECDH algorithm is not available.
     */
    public EcdhKeyAgreementParty(String party, ECGenParameterSpec agreedParameters)
        throws Exception {
        this.partyName = party;
        this.keyFactory = KeyFactory.getInstance(ECDH, JCE);

        // Create the key pair.
        KeyPairGenerator aKpairGen = KeyPairGenerator.getInstance(ECDH, JCE);
        aKpairGen.initialize(agreedParameters, RAND);
        this.keyPair = aKpairGen.generateKeyPair();

        // Initialize the key agreement state holding object.
        this.keyAgree = KeyAgreement.getInstance(ECDH, JCE);
        this.keyAgree.init(this.keyPair.getPrivate(), agreedParameters);
    }


    /**
     * Get this party's public key in encoded form.
     *
     * @return Encoded public key.
     */
    public byte[] getPublicKeyBytes() {
        return this.keyPair.getPublic().getEncoded();
    }
    public byte[] getPrivateKeyBytes(){
    	return this.keyPair.getPrivate().getEncoded();
    }


    /**
     * Process a public key or intermediate key from a peer and produce an
     * intermediate key to be passed on to another peer.
     *
     * @param peerPublicKeyEncoded Encoded public key or intermediate key to
     *  be processed.
     * @return encoded Intermediate key to be processed by the next peer.
     * @throws InvalidKeySpecException If the array of bytes from the peer does
     *  not represent a valid ECC key.
     * @throws InvalidKeyException If the public key's parameters do not match
     *  the parameters for this key.
     */
    public byte[] doIntermediatePhase(byte[] peerPublicKeyEncoded)
            throws  InvalidKeySpecException, InvalidKeyException {
        // Instantiate the public key based on the encoding from the peer.
        PublicKey peerPubKey = this.keyFactory.generatePublic(
                new X509EncodedKeySpec(peerPublicKeyEncoded));
        // Combine the peer or intermediate key and generate another intermediate
        // key.
        Key intermediateKey = this.keyAgree.doPhase(peerPubKey, false);
        return intermediateKey.getEncoded();
    }


    /**
     * Take an intermediate key from a peer and create the shared secret. The
     * intermediate key passed to this method must have been processed by all
     * of the other parties, except for the party which generated the public
     * key.
     *
     * @param peerPublicKeyEncoded Encoded intermediate key to be processed.
     * @throws InvalidKeySpecException If the array of bytes from the peer does
     *  not represent a valid ECC key.
     * @throws InvalidKeyException If the public key's parameters do not match
     *  the parameters for this key.
     * @throws NoSuchAlgorithmException If unexpectedly AES is not supported.
     */
    public void doFinalPhase(byte[] peerPublicKeyEncoded)
            throws  InvalidKeySpecException, InvalidKeyException, NoSuchAlgorithmException {
        // Instantiate the public key based on the encoding from the peer.
        PublicKey peerPubKey = this.keyFactory.generatePublic(
                new X509EncodedKeySpec(peerPublicKeyEncoded));
        //***************************//
//        BigInteger Order = ((ECKey)peerPubKey).getParams().getOrder();
//        BigInteger a     = ((ECKey)peerPubKey).getParams().getCurve().getA();
//        BigInteger b     = ((ECKey)peerPubKey).getParams().getCurve().getB();
//        int Confactor     = ((ECKey)peerPubKey).getParams().getCofactor();
        
        // Process the final peer key.
        this.keyAgree.doPhase(peerPubKey, true);
        // Generate the shared secret key.
        byte[] sharedSecret = this.keyAgree.generateSecret();
       // System.out.println("share + ")
//        KeyGenerator generator = KeyGenerator.getInstance("AES");
//        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
//        secureRandom.setSeed(sharedSecret);
//        generator.init(256, secureRandom);
//        
//        
//        this.sharedSecretKey = generator.generateKey();
        SecretKeyFactory aesFac = SecretKeyFactory.getInstance(AES, JCE);
        this.sharedSecretKey = aesFac.generateSecret(new SecretKeySpec(sharedSecret, AES));
    }


    /**
     * Display this party's shared secret.
     */
    public byte[] showSharedSecret() {
        System.out.println(this.partyName + "'s secret:");
        PrintBuffer.printBuffer(this.sharedSecretKey.getEncoded());
        return this.sharedSecretKey.getEncoded();
    }


    /**
     * Encrypt some data based on the agreed key.
     *
     * @return IV and plain text. [0] contains the IV and [1] contains the cipher text.
     * @throws Exception if there is a problem initializing the cipher object.
     */
    public byte[]encrypt(byte[] iv, Key Key,byte[] plaintext)
            throws Exception {
        System.out.println(this.partyName);

        // Generate a random IV for each encryption

        PrintBuffer.printBuffer(iv);
        
        GCMParameterSpec gcmParams = new GCMParameterSpec(iv);

        // Get a cipher object for AES encryption with Galois Counter Mode
        // and no padding.  Note that GCM mode is like a stream cipher, so
        // no padding is needed, even if the plaintext length is not a
        // multiple of the block size.
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", JCE);
        
        // Initialize the encryption object.  This call will
        // set up aes to perform encryption using AES.
        aes.init(Cipher.ENCRYPT_MODE, Key, gcmParams);

        // As the amount of plain text is small, do all of the processing in
        // one go.
        byte[] ciphertext = aes.doFinal(plaintext);
        System.out.println("Cipher LENGTH : " + ciphertext.length);

        PrintBuffer.printBuffer(ciphertext);

        return ciphertext;
    }


    /**
     * Decrypt some data based on the agreed key.
     *
     * @param ivAndCiphertext [0] contains the IV and [1] contains the cipher text.
     * @throws Exception if there is a problem initializing the cipher object.
     */
    public byte[] decrypt(byte[] iv, Key key,byte[] ciphertext)
            throws Exception {
        System.out.println(this.partyName);

        // Create a cipher object to decrypt the data.
        GCMParameterSpec gcmParams = new GCMParameterSpec(iv);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", JCE);

        // Initialize the decryption object.  This call will
        // set up aes to perform decryption using AES.
        aes.init(Cipher.DECRYPT_MODE, key, gcmParams);

        // As the amount of plain text is small, do all of the processing in
        // one go.
        byte[] plaintext = aes.doFinal(ciphertext);
        System.out.println("plaintext: ");
        PrintBuffer.printBuffer(plaintext);
        return plaintext;
    }

}
