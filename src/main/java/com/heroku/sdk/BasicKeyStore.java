package com.heroku.sdk;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static java.lang.String.format;

/**
 * This class is used to create a java.security.KeyStore from environment variables.
 *
 * @author Joe Kutner
 */
public class BasicKeyStore {

  private String password;

  private java.security.KeyStore keystore;

  protected static final String DEFAULT_TYPE = "PKCS12";

  public BasicKeyStore(String key, String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.password = password;

    this.keystore = createKeyStore(
        new StringReader(key),
        new StringReader(cert),
        password
    );
  }

  public BasicKeyStore(String cert, String password)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.password = password;

    this.keystore = createTrustStore(
        new StringReader(cert)
    );
  }

  public BasicKeyStore(String cert, String password, X509Certificate[] acceptedIssuers)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    this.password = password;

    this.keystore = createTrustStore(
        new StringReader(cert),
        acceptedIssuers
    );
  }

  public String password() {
    return this.password;
  }

  public java.security.KeyStore keyStore() {
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

  protected static java.security.KeyStore createKeyStore(final Reader keyReader, final Reader certReader, final String password)
      throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
    PrivateKey key = getPrivateKeyFromPEM(keyReader);
    keyReader.close();

    PEMParser parser = new PEMParser(certReader);
    java.security.KeyStore ks = java.security.KeyStore.getInstance(DEFAULT_TYPE);
    ks.load(null);

    List<X509Certificate> certificates = new ArrayList<>();

    X509Certificate certificate;
    while ((certificate = parseCert(parser)) != null) {
      certificates.add(certificate);
    }

    ks.setKeyEntry("alias", key, password.toCharArray(), certificates.toArray(new X509Certificate[]{}));

    parser.close();
    return ks;
  }

  protected static PrivateKey getPrivateKeyFromPEM(final Reader keyReader)
      throws IOException {
    final JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

    final PEMParser pem = new PEMParser(keyReader);

    PrivateKey key;
    Object pemContent = pem.readObject();
    if (pemContent instanceof PEMKeyPair) {
      PEMKeyPair pemKeyPair = (PEMKeyPair) pemContent;
      KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);
      key = keyPair.getPrivate();
    } else if (pemContent instanceof PrivateKeyInfo) {
      PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemContent;
      key = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
    } else {
      throw new IllegalArgumentException("Unsupported private key format '" + pemContent.getClass().getSimpleName() + '"');
    }

    pem.close();
    return key;
  }

  protected static java.security.KeyStore createTrustStore(final Reader certReader)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    return createTrustStore(certReader, new X509Certificate[]{});
  }

  protected static java.security.KeyStore createTrustStore(final Reader certReader, final X509Certificate[] acceptedIssuers)
      throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    PEMParser parser = new PEMParser(certReader);

    java.security.KeyStore ks = java.security.KeyStore.getInstance(DEFAULT_TYPE);
    ks.load(null);

    int i = 0;

    for (X509Certificate certificate : acceptedIssuers) {
      ks.setCertificateEntry(format("alias%d", i), certificate);
      i += 1;
    }

    X509Certificate certificate;
    while ((certificate = parseCert(parser)) != null) {
      ks.setCertificateEntry(format("alias%d", i), certificate);
      i += 1;
    }

    parser.close();

    return ks;
  }

  protected static X509Certificate parseCert(PEMParser parser) throws IOException, CertificateException {
    X509CertificateHolder certHolder = (X509CertificateHolder) parser.readObject();
    if (certHolder == null) {
      return null;
    }
    return new JcaX509CertificateConverter().getCertificate(certHolder);
  }
}
