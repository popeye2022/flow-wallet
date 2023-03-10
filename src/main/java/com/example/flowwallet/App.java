package com.example.flowwallet;

import com.nftco.flow.sdk.*;
import com.nftco.flow.sdk.Signer;
import com.nftco.flow.sdk.cadence.AddressField;
import com.nftco.flow.sdk.cadence.StringField;
import com.nftco.flow.sdk.cadence.UFix64NumberField;
import com.nftco.flow.sdk.crypto.Crypto;
import com.nftco.flow.sdk.crypto.KeyPair;
import com.nftco.flow.sdk.crypto.PrivateKey;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
public final class App {
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = Crypto.generateKeyPair(SignatureAlgorithm.ECDSA_P256);

        String privateKye = "00970f0c8b7dee62add01a16c0ea025d11c0e44cd553667a9c08b4fd7cef34ccf4";

        PrivateKey privateKey1 = Crypto.decodePrivateKey(privateKye);
        System.err.println(privateKey1.getHex());


        App appNew = new App(privateKye);
        String publicKey = "a07b0f9f0834398d7dcb2b3c978629455bc30b817392a8487c97cb17f555eb3f526519024caade84a9b039df75f70ba3ec1ef7f5d9812b8980ffdcf031e874ed";

//        PrivateKey privateKey1 = Crypto.decodePrivateKey(privateKye);

        FlowAddress sender = new FlowAddress("0xe5bba85f3ad94fbe");
        FlowAddress recipientAddress = new FlowAddress("0x656d3fe8b0979cc5");

        appNew.createAccount(sender,publicKey);
//        appNew.transferTokens(sender,recipientAddress,new BigDecimal("1.12345678"));
    }

    private final FlowAccessApi accessAPI;
    private final PrivateKey privateKey;

    public App(String privateKeyHex) {
        this.accessAPI = Flow.newAccessApi("access.devnet.nodes.onflow.org");
        this.privateKey = Crypto.decodePrivateKey(privateKeyHex);
    }

    public FlowAddress createAccount(FlowAddress payerAddress, String publicKeyHex) {
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

        com.nftco.flow.sdk.Signer signer = Crypto.getSigner(this.privateKey, payerAccountKey.getHashAlgo());
//        tx = tx.addPayloadSignature(payerAddress, 0, signer);
        tx = tx.addEnvelopeSignature(payerAddress, 0, signer);


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

        Signer signer = Crypto.getSigner(this.privateKey, senderAccountKey.getHashAlgo());
        tx = tx.addEnvelopeSignature(senderAddress, senderAccountKey.getId(), signer);

        FlowId txID = this.accessAPI.sendTransaction(tx);
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
}