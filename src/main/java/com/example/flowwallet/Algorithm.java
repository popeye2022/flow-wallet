/*
 * Copyright (c) 2018, Circle Internet Financial Trading Company Limited.
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
 */

package com.example.flowwallet;

import org.bouncycastle.crypto.signers.Ed25519Signer;

public enum Algorithm {
    secp256k1randomK,
    secp256k1,
    ed25519,
    rsa,
    secp256k1steem,
    ed25519nem,
    masterKey,
    curve25519Nxt,
    ed25519ada,
    secp256r1,
    ed25519xmr,
    ;

    private boolean testnet = false;

    public boolean isTestnet() {
        return testnet;
    }

    public void setTestnet(boolean testnet) {
        this.testnet = testnet;
    }

    /**
     * Helper method to retrieve a {@link Signer} for the specified algorithm
     * @param alg   the algorithm to lookup
     * @return      a {@link Signer} for that algorithm
     */

}
