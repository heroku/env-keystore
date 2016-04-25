package com.github.jkutner;

import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;

public class EnvKeyStore extends KeyStore {
  /**
   * Creates a KeyStore object of the given type, and encapsulates the given
   * provider implementation (SPI object) in it.
   *
   * @param keyStoreSpi the provider implementation.
   * @param provider    the provider.
   * @param type        the keystore type.
   */
  protected EnvKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
    super(keyStoreSpi, provider, type);
  }
}
