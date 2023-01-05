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

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

/**
 * Interface to handle signing/public key generation in a variety of algorithms.
 */
public interface Signer {

    /**
     * Generate a new private ket
     * @param secureRandom a source of randomness
     * @return a new private key
     */
    byte[] newKey(SecureRandom secureRandom);

    /**
     * Generate new private ket by keyPath
     * @param masterKeyId
     * @param keyPath
     * @return
     */
    byte[] hdKey(UUID masterKeyId, String keyPath);

    /**
     * Generate a public key for the given private key
     * @param privateKey    the private key
     * @return              A DER encoded X.509 SubjectPublicKeyInfo
     */
    byte[] publicKey(byte[] privateKey);


    /**
     * Sign a message with the given private key
     * @param message       the message to sign
     * @param privateKey    the key to sign the message with
     * @return              A DER encoded signature - r, s
     */
    byte[] signMsg(byte[] message, byte[]privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException;

    /**
     * Validates a private key.
     * @param   privateKey  the private key to validate
     * @return              true if validation succeeds, false otherwise
     */
    boolean validate(byte[] privateKey);

    /**
     * Exports the viewing key, currently only required for XMR (Monero)
     */
    default byte[] exportViewKey(byte[] privateKey) {
        throw new UnsupportedOperationException("Signer does not support this operation");
    }
}
