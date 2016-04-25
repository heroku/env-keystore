package com.github.jkutner;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.security.cert.CertificateException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class Main {

  public static void main(String[] args) throws Exception {
    String kafkaClientCertKey = System.getenv("KAFKA_CLIENT_CERT_KEY");
    String kafkaClientCert = System.getenv("KAFKA_CLIENT_CERT");
    //String kafkaTrustedCert = System.getenv("KAFKA_TRUSTED_CERT");

    KeyStore ks = convertPEMToPKCS12(
        new StringReader(kafkaClientCertKey),
        new StringReader(kafkaClientCert),
        "password");

    System.out.println(ks.size());

    // write the file?
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ks.store(bos, "password".toCharArray());
    bos.close();

    Files.write(Paths.get("keystore.pkcs12"), bos.toByteArray());
  }


  public static KeyStore convertPEMToPKCS12(final Reader keyReader, final Reader clientCertReader, final String password)
      throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, java.security.cert.CertificateException {

    // Get the private key
    PEMParser pem = new PEMParser(keyReader);
    PEMKeyPair pemKeyPair = ((PEMKeyPair) pem.readObject());
    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
    KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);

    PrivateKey key = keyPair.getPrivate();

    pem.close();
    keyReader.close();

    // Get the certificate
    pem = new PEMParser(clientCertReader);

    X509CertificateHolder certHolder = (X509CertificateHolder) pem.readObject();
    java.security.cert.Certificate X509Certificate =
        new JcaX509CertificateConverter().getCertificate(certHolder);

    pem.close();
    clientCertReader.close();

    // Put them into a PKCS12 keystore
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null);
    ks.setKeyEntry("alias", key, password.toCharArray(),
        new java.security.cert.Certificate[]{X509Certificate});
    return ks;
  }
}
