package com.github.jkutner;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
   * @return an EnvKeyStore with a loaded TrustStore
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public static EnvKeyStore create(final String trustEnvVar)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new EnvKeyStore(
        System.getenv(trustEnvVar)
    );
  }

  private String password;

  private KeyStore keystore;

  EnvKeyStore(String key, String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.password = password;

    this.keystore = createKeyStore(
        new StringReader(key),
        new StringReader(cert),
        password
    );
  }

  EnvKeyStore(String cert)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.keystore = createTrustStore(
        new StringReader(cert)
    );
  }

  public String password() {
    return this.password;
  }

  public KeyStore keyStore() {
    return this.keystore;
  }

  public InputStream toInputStream() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    this.store(bos);
    bos.close();

    return new ByteArrayInputStream(bos.toByteArray());
  }

  public void store(OutputStream out) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.keystore.store(out, password.toCharArray());
  }

//  public void store(Path path) {
//
//  }
//
//  public void storeTemp() {
//
//  }

  public static KeyStore createKeyStore(final Reader keyReader, final Reader certReader, final String password)
      throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {

    // Get the private key
    PEMParser pem = new PEMParser(keyReader);
    PEMKeyPair pemKeyPair = ((PEMKeyPair) pem.readObject());
    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
    KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
    PrivateKey key = keyPair.getPrivate();
    pem.close();
    keyReader.close();

    X509Certificate certificate = parseCert(certReader);

    // Put them into a PKCS12 keystore
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null);
    ks.setKeyEntry("alias", key, password.toCharArray(), new X509Certificate[]{certificate});
    return ks;
  }

  private static KeyStore createTrustStore(final Reader certReader)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    X509Certificate certificate = parseCert(certReader);

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null);
    ks.setCertificateEntry("alias", certificate);
    return ks;
  }

  private static X509Certificate parseCert(final Reader certReader) throws IOException, CertificateException {
    PEMParser pem = new PEMParser(certReader);
    X509CertificateHolder certHolder = (X509CertificateHolder) pem.readObject();
    X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
    pem.close();
    return certificate;
  }
}
