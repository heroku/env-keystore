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
import java.util.function.Consumer;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

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

  private String password;

  private KeyStore keystore;

  private static final String DEFAULT_TYPE = "PKCS12";

  EnvKeyStore(String key, String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.password = password;

    this.keystore = createKeyStore(
        new StringReader(key),
        new StringReader(cert),
        password
    );
  }

  EnvKeyStore(String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.password = password;

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

  public String type() {
    return DEFAULT_TYPE;
  }

  public InputStream toInputStream() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    return new ByteArrayInputStream(toBytes());
  }

  public byte[] toBytes() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    this.store(bos);
    bos.close();
    return bos.toByteArray();
  }

  public void store(OutputStream out) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.keystore.store(out, password.toCharArray());
  }

  public void store(Path path) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    Files.write(path, toBytes());
  }

  public File storeTemp() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    File temp = File.createTempFile("env-keystore", type().toLowerCase());
    store(temp.toPath());
    return temp;
  }

  public void asFile(Consumer<File> c) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    File temp = storeTemp();
    c.accept(temp);
    Files.delete(temp.toPath());
  }

  private static KeyStore createKeyStore(final Reader keyReader, final Reader certReader, final String password)
      throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
    PEMParser pem = new PEMParser(keyReader);
    PEMKeyPair pemKeyPair = ((PEMKeyPair) pem.readObject());
    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
    KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
    PrivateKey key = keyPair.getPrivate();
    pem.close();
    keyReader.close();

    PEMParser parser = new PEMParser(certReader);
    X509Certificate certificate = parseCert(parser);
    parser.close();

    KeyStore ks = KeyStore.getInstance(DEFAULT_TYPE);
    ks.load(null);
    ks.setKeyEntry("alias", key, password.toCharArray(), new X509Certificate[]{certificate});
    return ks;
  }

  private static KeyStore createTrustStore(final Reader certReader)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    PEMParser parser = new PEMParser(certReader);

    KeyStore ks = KeyStore.getInstance(DEFAULT_TYPE);
    ks.load(null);

    int i = 0;
    X509Certificate certificate;

    while ((certificate = parseCert(parser)) != null) {
      ks.setCertificateEntry(format("alias%d", i), certificate);
      i += 1;
    }

    parser.close();

    return ks;
  }

  private static X509Certificate parseCert(PEMParser parser) throws IOException, CertificateException {
    X509CertificateHolder certHolder = (X509CertificateHolder) parser.readObject();
    if (certHolder == null) {
      return null;
    }
    X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
    return certificate;
  }
}
