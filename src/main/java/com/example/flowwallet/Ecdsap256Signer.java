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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Implement signing/public key generation for secp256k1 which is used in ethereum/bitcoin/bitcoin derived currencies
 */
public class Ecdsap256Signer implements Signer {
    static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("P-256");
    static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

    private Secp256k1Type type;

    public Ecdsap256Signer() {
        this(Secp256k1Type.standard);
    }

    public Ecdsap256Signer(Secp256k1Type type) {
        this.type = type;
    }

    public Ecdsap256Signer(boolean useRandomK) {
        this.type = useRandomK ? Secp256k1Type.randomK : Secp256k1Type.standard;
    }

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

    @Override
    public byte[] publicKey(byte[] privateKey) {
        ECPoint q = new FixedPointCombMultiplier().multiply(CURVE.getG(), new BigInteger(1, privateKey));
        ECPublicKeyParameters p = new ECPublicKeyParameters(q, CURVE);
        try {
            byte[] pubBytes = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(p).getEncoded(ASN1Encoding.DER);
            return pubBytes;
        } catch (IOException io) {
            throw new RuntimeException(io);
        }
    }

    @Override
    public byte[] signMsg(byte[] msg, byte[] privateKey) {
        DSA signer;

        switch (type) {
            case standard:
            default:
                signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
                break;
            case randomK:
                signer = new ECDSASigner(new RandomDSAKCalculator());
                break;
        }

        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(new BigInteger(1, privateKey), CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(msg);

        ECDSASignature ecdsaSig = new ECDSASignature(components[0], components[1]).toCanonicalised();

        ByteArrayOutputStream baos = new ByteArrayOutputStream(72);
        try {
            DERSequenceGenerator der = new DERSequenceGenerator(baos);
            der.addObject(new ASN1Integer(ecdsaSig.r));
            der.addObject(new ASN1Integer(ecdsaSig.s));
            der.close();
            byte[] sig = baos.toByteArray();
            return sig;
        } catch (IOException e) {
            // TODO: log
            return null;
        }
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
