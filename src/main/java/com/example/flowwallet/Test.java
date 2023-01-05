package com.example.flowwallet;

import com.nftco.flow.sdk.SignatureAlgorithm;
import com.nftco.flow.sdk.crypto.Crypto;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, DecoderException, InvalidKeySpecException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String s = Hex.encodeHexString("123".getBytes());
        System.err.println(s);
        BigInteger bigInteger = new BigInteger("123", 16);
        System.err.println(bigInteger);

        Secp256r1Signer secp256r1Signer = new Secp256r1Signer();
        com.nftco.flow.sdk.crypto.KeyPair keyPair = Crypto.generateKeyPair(SignatureAlgorithm.ECDSA_P256);

        String privateKye = "00970f0c8b7dee62add01a16c0ea025d11c0e44cd553667a9c08b4fd7cef34ccf4";
        byte[] bytes = secp256r1Signer.recoverKey(privateKye);
        byte[] publicBytes = secp256r1Signer.publicKey(bytes);
        System.err.println(Hex.encodeHex(publicBytes));
        com.nftco.flow.sdk.crypto.PrivateKey privateKey1 = Crypto.decodePrivateKey(privateKye);
        System.err.println(privateKey1.getHex());


//        String privateKey = "5f255277956f208119bbd3419840f93fa107660f16441eef63531c143f3a339e";
//        Ecdsap256Signer ecdsap256Signer = new Ecdsap256Signer();
////        byte[] bytes1 = ecdsap256Signer.newKey(new SecureRandom());
////        System.err.println(Hex.encodeHex(bytes1));
//
//        byte[] bytes = ecdsap256Signer.publicKey(Hex.decodeHex(privateKey));
//        System.err.println("publickey : " + Hex.encodeHexString(bytes));
//
//        com.nftco.flow.sdk.crypto.PrivateKey privateKeySDK = Crypto.decodePrivateKey(privateKey);
//        Signer signer = Crypto.getSigner(privateKeySDK, HashAlgorithm.SHA2_256);
//        byte[] sign = signer.sign("123".getBytes());

    }

    public static byte[] createKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        System.err.println(keyPair.getPrivate().getAlgorithm());
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keyPair.getPrivate();
        byte[] bytes = privParams.getD().toByteArray();
        return bytes;
    }


    public static void verify(String privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(privateKey, 16), parameterSpec);
        PrivateKey privateKey1 = keyFactory.generatePrivate(ecPrivateKeySpec);

        System.err.println(privateKey1);
    }

}
