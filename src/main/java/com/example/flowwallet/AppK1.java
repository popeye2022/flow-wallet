package com.example.flowwallet;

import com.nftco.flow.sdk.*;
import com.nftco.flow.sdk.cadence.AddressField;
import com.nftco.flow.sdk.cadence.StringField;
import com.nftco.flow.sdk.cadence.UFix64NumberField;
import com.nftco.flow.sdk.crypto.Crypto;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public final class AppK1 {
    public static void main(String[] args) throws Exception {

    }

    private final FlowAccessApi accessAPI;
    private final com.nftco.flow.sdk.crypto.PrivateKey privateKey;

    public AppK1(String privateKeyHex) {
        this.accessAPI = Flow.newAccessApi("access.devnet.nodes.onflow.org");
        this.privateKey = Crypto.decodePrivateKey(privateKeyHex);
    }

    public FlowAddress createAccount(FlowAddress payerAddress, String publicKeyHex) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        FlowAccountKey payerAccountKey = this.getAccountKey(payerAddress, 0);
        System.err.println("SequenceNumber() = " + payerAccountKey.getSequenceNumber());
        FlowAccountKey newAccountPublicKey = new FlowAccountKey(
                0,
                new FlowPublicKey(publicKeyHex),
                SignatureAlgorithm.ECDSA_P256,
                HashAlgorithm.SHA2_256,
                1000,
                0,
                false);

        TransactionBuilder transactionBuilder = new TransactionBuilder();
        FlowTransaction tx = new FlowTransaction(
                new FlowScript(loadScript("create_account.cdc")),
                Arrays.asList(new FlowArgument(new StringField(Hex.toHexString(newAccountPublicKey.getEncoded())))),
                this.getLatestBlockID(),
                999L,
                new FlowTransactionProposalKey(
                        payerAddress,
                        payerAccountKey.getId(),
                        payerAccountKey.getSequenceNumber()),
                payerAddress,
                Arrays.asList(payerAddress),
                new ArrayList<>(),
                new ArrayList<>());

//        Signer signer = Crypto.getSigner(this.privateKey, payerAccountKey.getHashAlgo());
//        tx = tx.addPayloadSignature(payerAddress, 0, signer);
        byte[] transaction_domain_tag = DomainTag.getTRANSACTION_DOMAIN_TAG();
        byte[] canonicalAuthorizationEnvelope = tx.getCanonicalAuthorizationEnvelope();



        Secp256r1Signer ecdsap256Signer1 = new Secp256r1Signer();
        byte[] privateKey = ecdsap256Signer1.recoverKey(this.privateKey.getHex());
        byte[] signResult = ecdsap256Signer1.signMsg(ByteUtils.combineByte(transaction_domain_tag,canonicalAuthorizationEnvelope), privateKey);

        FlowSignature flowSignature = new FlowSignature(signResult);
        tx = tx.addEnvelopeSignature(payerAddress, 0, flowSignature);

        FlowId txID = this.accessAPI.sendTransaction(tx);
        System.err.println("txID = " + txID.getBase16Value());
        FlowTransactionResult txResult = this.waitForSeal(txID);

        return this.getAccountCreatedAddress(txResult);
    }

    public void transferTokens(FlowAddress senderAddress, FlowAddress recipientAddress, BigDecimal amount) throws Exception {
        // exit early
        if (amount.scale() != 8) {
            throw new Exception("FLOW amount must have exactly 8 decimal places of precision (e.g. 10.00000000)");
        }

        FlowAccountKey senderAccountKey = this.getAccountKey(senderAddress, 0);
        FlowTransaction tx = new FlowTransaction(
                new FlowScript(loadScript("transfer_flow_testnet.cdc")),
                Arrays.asList(
                        new FlowArgument(new UFix64NumberField(amount.toPlainString())),
                        new FlowArgument(new AddressField(recipientAddress.getBase16Value()))),
                this.getLatestBlockID(),
                100L,
                new FlowTransactionProposalKey(
                        senderAddress,
                        senderAccountKey.getId(),
                        senderAccountKey.getSequenceNumber()),
                senderAddress,
                Arrays.asList(senderAddress),
                new ArrayList<>(),
                new ArrayList<>());

//        Signer signer = Crypto.getSigner(this.privateKey, senderAccountKey.getHashAlgo());
//        tx = tx.addEnvelopeSignature(senderAddress, senderAccountKey.getId(), signer);

        byte[] transaction_domain_tag = DomainTag.getTRANSACTION_DOMAIN_TAG();
        byte[] canonicalAuthorizationEnvelope = tx.getCanonicalAuthorizationEnvelope();

        Secp256r1Signer ecdsap256Signer1 = new Secp256r1Signer();
        byte[] privateKey = ecdsap256Signer1.recoverKey(this.privateKey.getHex());
        byte[] signResult = ecdsap256Signer1.signMsg(ByteUtils.combineByte(transaction_domain_tag,canonicalAuthorizationEnvelope), privateKey);

        FlowSignature flowSignature = new FlowSignature(signResult);
        tx = tx.addEnvelopeSignature(senderAddress, 0, flowSignature);


        FlowId txID = this.accessAPI.sendTransaction(tx);
        System.err.println("txId = " + txID);
        this.waitForSeal(txID);
    }

    public FlowAccount getAccount(FlowAddress address) {
        FlowAccount ret = this.accessAPI.getAccountAtLatestBlock(address);
        return ret;
    }

    public BigDecimal getAccountBalance(FlowAddress address) {
        FlowAccount account = this.getAccount(address);
        return account.getBalance();
    }

    private FlowId getLatestBlockID() {
        return this.accessAPI.getLatestBlockHeader().getId();
    }

    private FlowAccountKey getAccountKey(FlowAddress address, int keyIndex) {
        FlowAccount account = this.getAccount(address);
        return account.getKeys().get(keyIndex);
    }

    private FlowTransactionResult getTransactionResult(FlowId txID) {
        FlowTransactionResult result = this.accessAPI.getTransactionResultById(txID);
        return result;
    }

    private FlowTransactionResult waitForSeal(FlowId txID) {
        FlowTransactionResult txResult;

        while(true) {
            txResult = this.getTransactionResult(txID);
            if (txResult.getStatus().equals(FlowTransactionStatus.SEALED)) {
                return txResult;
            }

            try {
                Thread.sleep(1000L);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private FlowAddress getAccountCreatedAddress(FlowTransactionResult txResult) {
        if (!txResult.getStatus().equals(FlowTransactionStatus.SEALED)
                || txResult.getErrorMessage().length() > 0) {
            return null;
        }

        String rez = txResult
                .getEvents()
                .get(0)
                .getEvent()
                .getValue()
                .getFields()[0]
                .getValue()
                .getValue().toString();
        return new FlowAddress(rez.substring(2));
    }

    private byte[] loadScript(String name) {
        try (InputStream is = this.getClass().getClassLoader().getResourceAsStream(name);) {
            return is.readAllBytes();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void verfy() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Ecdsap256Signer signer = new Ecdsap256Signer();
        byte[] privateKeyByte = Hex.decode("00970f0c8b7dee62add01a16c0ea025d11c0e44cd553667a9c08b4fd7cef34ccf4");
        byte[] msg = Hex.decode("9a1313b56df11aa87cb3021787a2414666cae4795fbc25a4b153ce37efe695a9");
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(privateKeyByte), parameterSpec);
        PrivateKey privateKey = keyFactory.generatePrivate(ecPrivateKeySpec);

        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(msg);
        byte[] sign = ecdsaSign.sign();


        ECPoint q = new FixedPointCombMultiplier().multiply(Ecdsap256Signer.CURVE.getG(), new BigInteger(1,privateKeyByte));
        ECPoint ecPoint = Secp256r1Signer.CURVE.getCurve().decodePoint(q.getEncoded(true));
        org.bouncycastle.jce.spec.ECPublicKeySpec ecPublicKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(ecPoint,parameterSpec);
        PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
        ECPublicKey ecPublicKeytemp = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
        byte[] pubkeyBytes = ByteUtils.combineByte(ecPublicKeytemp.getQ().getXCoord().getEncoded(), ecPublicKeytemp.getQ().getYCoord().getEncoded());

        ecdsaSign.initVerify(publicKey);
        System.err.println("publickey = "+ Hex.toHexString(publicKey.getEncoded()));
        byte[] msg2 = Hex.decode("9a1313b56df11aa87cb3021787a2414666cae4795fbc25a4b153ce37efe695");
        ecdsaSign.update(msg2);
        boolean verify = ecdsaSign.verify(signer.signMsg(msg2,privateKeyByte));
        System.err.println(verify);

        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        ECNamedCurveSpec params = new ECNamedCurveSpec("P-256", ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());

        byte[] bytes1 = {4};
        byte[] bytes = ByteUtils.combineByte(bytes1,pubkeyBytes);
        int v3 = (Ecdsap256Signer.CURVE.getCurve().getFieldSize() + 7) / 8;
        int v1 = bytes.length;
        if(v1 != v3+1){
            System.err.println("v1 = " + v1 + "    v3 = " + v3);
        }

        java.security.spec.ECPoint pPoint = ECPointUtil.decodePoint(params.getCurve(),bytes);
        java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(pPoint, params);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
        ecdsaSign.initVerify(ecPublicKey);
        byte[] msg3 = Hex.decode("9a1313b56df11aa87cb3021787a2414666cae4795fbc25a4b153ce37efe695");
        ecdsaSign.update(msg3);
        boolean verifyReuslt = ecdsaSign.verify(signer.signMsg(msg3,privateKeyByte));
        System.err.println(verifyReuslt);
    }
}