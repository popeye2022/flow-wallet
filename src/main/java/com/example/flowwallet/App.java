package com.example.flowwallet;

import com.nftco.flow.sdk.*;
import com.nftco.flow.sdk.cadence.AddressField;
import com.nftco.flow.sdk.cadence.StringField;
import com.nftco.flow.sdk.cadence.UFix64NumberField;
import com.nftco.flow.sdk.crypto.Crypto;
import com.nftco.flow.sdk.crypto.PrivateKey;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;

public final class App {
    public static void main(String[] args) {

        String privateKye = "3f6012913ff4d62cfabf0449735c521a1dc1ade840fcce20be510c27d9ad4460";

        App appNew = new App(privateKye);
        String publicKey = "14d199368ef3cf4b3dc283fb6a55edb0793bba133e53d993b854cd88ade7e8f204189e9a709f5fe375a53340f307fc795d0aa5855859b5410443fba9ba0bdae1";

//        PrivateKey privateKey1 = Crypto.decodePrivateKey(privateKye);

        appNew.createAccount(new FlowAddress("0x014b5a59a4349835"),publicKey);
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
                SignatureAlgorithm.ECDSA_SECP256k1,
                HashAlgorithm.SHA2_256,
                1,
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

        Signer signer = Crypto.getSigner(this.privateKey, payerAccountKey.getHashAlgo());
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
                new FlowScript(loadScript("transfer_flow.cdc")),
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
