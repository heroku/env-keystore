package com.heroku.sdk;

import static java.lang.String.format;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * This class is used to create a java.security.KeyStore from environment variables.
 *
 * @author Joe Kutner
 */
public class EnvKeyStore {

  /**
   * Create a KeyStore representation from environment variables.
   *
   * @param keyEnvVar The environment variable name of the key
   * @param certEnvVar The environment variable name of the certificate
   * @param passwordEnvVar The environment variable name of the password
   * @return an EnvKeyStore with a loaded KeyStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore create(final String keyEnvVar, final String certEnvVar, final String passwordEnvVar)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(
        System.getenv(keyEnvVar),
        System.getenv(certEnvVar),
        System.getenv(passwordEnvVar)
    );
  }

  /**
   * Create a TrustStore representation from an environment variable.
   *
   * @param trustEnvVar The environment variable name of the certificate
   * @param passwordEnvVar The environment variable name of the password
   * @return an EnvKeyStore with a loaded TrustStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore create(final String trustEnvVar, final String passwordEnvVar)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(
        System.getenv(trustEnvVar),
        System.getenv(passwordEnvVar)
    );
  }

  /**
   * Create a TrustStore representation from an environment variable and add it to the default TrustStore.
   *
   * @param trustEnvVar The environment variable name of the certificate
   * @return an EnvKeyStore with a loaded TrustStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore addToDefaultTrustStore(final String trustEnvVar)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    TrustManagerFactory tmf = TrustManagerFactory
        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);

    X509TrustManager defaultTm = null;
    for (TrustManager tm : tmf.getTrustManagers()) {
      if (tm instanceof X509TrustManager) {
        defaultTm = (X509TrustManager) tm;
        break;
      }
    }

    return new EnvKeyStore(
        System.getenv(trustEnvVar),
        new BigInteger(130, new SecureRandom()).toString(32),
        defaultTm == null ? new X509Certificate[]{} : defaultTm.getAcceptedIssuers()
    );
  }

  /**
   * Create a KeyStore representation from an environment variable.
   *
   * @param key The the certificate as a string
   * @param cert The certificate as a string
   * @param password The password as a string
   * @return an EnvKeyStore with a loaded TrustStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore createFromPEMStrings(final String key, final String cert, final String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(key, cert, password);
  }

  /**
   * Create a TrustStore representation from an environment variable.
   *
   * @param trust The the certificate as a string
   * @param password The password as a string
   * @return an EnvKeyStore with a loaded TrustStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore createFromPEMStrings(final String trust, final String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(trust, password);
  }

  /**
   * Create a KeyStore representation from environment variables.
   *
   * @param keyEnvVar The environment variable name of the key
   * @param certEnvVar The environment variable name of the certificate
   * @return an EnvKeyStore with a loaded KeyStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore createWithRandomPassword(final String keyEnvVar, final String certEnvVar)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(
        System.getenv(keyEnvVar),
        System.getenv(certEnvVar),
        new BigInteger(130, new SecureRandom()).toString(32)
    );
  }

  /**
   * Create a TrustStore representation from an environment variable.
   *
   * @param trustEnvVar The environment variable name of the certificate
   * @return an EnvKeyStore with a loaded TrustStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore createWithRandomPassword(final String trustEnvVar)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(
        System.getenv(trustEnvVar),
        new BigInteger(130, new SecureRandom()).toString(32)
    );
  }

  private BasicKeyStore basicKeyStore;

  EnvKeyStore(String key, String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    basicKeyStore = new BasicKeyStore(key, cert, password);
  }

  EnvKeyStore(String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.basicKeyStore = new BasicKeyStore(cert, password);
  }

  EnvKeyStore(String cert, String password, X509Certificate[] acceptedIssuers)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.basicKeyStore = new BasicKeyStore(cert, password, acceptedIssuers);
  }

  public String password() {
    return basicKeyStore.password();
  }

  public KeyStore keyStore() {
    return basicKeyStore.keyStore();
  }

  public String type() {
    return basicKeyStore.DEFAULT_TYPE;
  }

  public InputStream toInputStream() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return basicKeyStore.toInputStream();
  }

  public byte[] toBytes() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return basicKeyStore.toBytes();
  }

  public void store(OutputStream out) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    basicKeyStore.store(out);
  }

  public void store(Path path) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    basicKeyStore.store(path);
  }

  public File storeTemp() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    return basicKeyStore.storeTemp();
  }

  public void asFile(Consumer<File> c) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    basicKeyStore.asFile(c);
  }

}
