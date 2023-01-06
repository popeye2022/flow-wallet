/*
 * Copyright (c) 2017, Circle Internet Financial Trading Company Limited.
 * All rights reserved.
 *
 * Circle Internet Financial Trading Company Limited CONFIDENTIAL
 *
 * This file includes unpublished proprietary source code of Circle Internet
 * Financial Trading Company Limited, Inc. The copyright notice above does not
 * evidence any actual or intended publication of such source code. Disclosure
 * of this source code or any related proprietary information is strictly
 * prohibited without the express written permission of Circle Internet Financial
 * Trading Company Limited.
 *
 */
package com.example.flowwallet;

import com.nftco.flow.sdk.crypto.Crypto;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.encoders.Hex;


import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

/**
 * Implement signing/public key generation for secp256r1 which is used in neo
 */
public class Secp256r1Signer implements Signer {
    static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName(Algorithm.secp256r1.name());
    static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);


    public byte[] newKey(SecureRandom secureRandom) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return privParams.getD().toByteArray();
    }

    @Override
    public byte[] hdKey(UUID masterKeyId, String keyPath) {
        return null;
    }

    public byte[] recoverKey(String key) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
//        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
//        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
//        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(key, 16), ecParameterSpec);
//        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(ecPrivateKeySpec);
//
//        int i = ecPrivateKey.getParameters().getN().bitLength() / 8;
//        System.err.println("bitLength = " + i );
//        byte[] bytes = ecPrivateKey.getD().toByteArray();
//        String s = Hex.toHexString(bytes);
//        return bytes;

//        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(new BigInteger(1, Hex.decode(key)), CURVE);

        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(new BigInteger(key, 16), CURVE);
        System.err.println(Hex.toHexString(privParams.getD().toByteArray()));
        return privParams.getD().toByteArray();
    }

    @Override
    public byte[] publicKey(byte[] privateKey) {

        ECPoint q = new FixedPointCombMultiplier().multiply(CURVE.getG(), new BigInteger(1, privateKey));
        ECPublicKeyParameters p = new ECPublicKeyParameters(q, CURVE);
        return ByteUtils.combineByte(p.getQ().getXCoord().getEncoded(),p.getQ().getYCoord().getEncoded());
    }

    public void deocdepublickey(String pubkey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECNamedCurveSpec params = new ECNamedCurveSpec("P-256", ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        byte[] bytes = ByteUtils.combineByte(Hex.decode("04"), Hex.decode(pubkey));
        java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(params.getCurve(), bytes);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, params);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);

//        publicKey.q.xCoord.encoded + publicKey.q.yCoord.encoded
        byte[] bytes1 = ByteUtils.combineByte(ecPublicKey.getQ().getXCoord().getEncoded(), ecPublicKey.getQ().getYCoord().getEncoded());
        System.err.println("deocdepublickey = " + Hex.toHexString(bytes1));
    }
    @Override
    public byte[] signMsg(byte[] msg, byte[] privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        String key = Hex.toHexString(privateKey);
        System.err.println("signMsg key = " + key);
        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(privateKey), ecParameterSpec);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(ecPrivateKeySpec);

        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(ecPrivateKey);
        ecdsaSign.update(msg);

        byte[] sign = ecdsaSign.sign();

        byte[] bytes = Crypto.normalizeSignature(sign, 32);
        return sign;

    }

    public Boolean verifySing(byte[] sign,String pubkey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");

        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECNamedCurveSpec params = new ECNamedCurveSpec("P-256", ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        byte[] bytes = ByteUtils.combineByte(Hex.decode("04"), Hex.decode(pubkey));
        java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(params.getCurve(), bytes);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, params);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);


        ecdsaSign.initVerify(ecPublicKey);
        return ecdsaSign.verify(sign);
    }
    @Override
    public boolean validate(byte[] privateKey) {
        try {
            ECPrivateKeyParameters keyParams = new ECPrivateKeyParameters(new BigInteger(1, privateKey), CURVE);
            return keyParams.getD().bitLength() <= 32 * 8
                    && !keyParams.getD().equals(BigInteger.ZERO)
                    && !keyParams.getD().equals(BigInteger.ONE);
        } catch (Throwable t) {
            return false;
        }
    }

    private static class ECDSASignature {
        private final BigInteger r;
        private final BigInteger s;

        ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        /**
         * Returns true if the S component is "low", that means it is below
         * {@link #HALF_CURVE_ORDER}. See
         * <a href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">
         * BIP62</a>.
         */
        public boolean isCanonical() {
            return s.compareTo(HALF_CURVE_ORDER) <= 0;
        }

        /**
         * Will automatically adjust the S component to be less than or equal to half the curve
         * order, if necessary. This is required because for every signature (r,s) the signature
         * (r, -s (mod N)) is a valid signature of the same message. However, we dislike the
         * ability to modify the bits of a Bitcoin transaction after it's been signed, as that
         * violates various assumed invariants. Thus in future only one of those forms will be
         * considered legal and the other will be banned.
         */
        public ECDSASignature toCanonicalised() {
            if (!isCanonical()) {
                // The order of the curve is the number of valid points that exist on that curve.
                // If S is in the upper half of the number of valid points, then bring it back to
                // the lower half. Otherwise, imagine that
                //    N = 10
                //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
                //    10 - 8 == 2, giving us always the latter solution, which is canonical.
                return new ECDSASignature(r, CURVE.getN().subtract(s));
            } else {
                return this;
            }
        }
    }

}
