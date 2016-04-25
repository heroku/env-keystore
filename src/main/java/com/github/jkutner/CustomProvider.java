package com.github.jkutner;

import javax.security.cert.CertificateException;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class CustomProvider extends Provider {

  private static final String INFO = "ENV " +
      "(DSA key/parameter generation; DSA signing; " +
      "SHA-1, MD5 digests; SecureRandom; X.509 certificates; JKS keystore)";

  public CustomProvider() {
    super("ENV", 1.2, INFO);

    AccessController.doPrivileged(new java.security.PrivilegedAction() {
      public Object run() {
        put("KeyStore.ENV", "com.github.jkutner.EnvKeyStore");
        put("KeyStore.ENV ImplementedIn", "Software");
        return null;
      }
    });
  }

  public static byte[] convertPEMToPKCS12(final String keyFile, final String cerFile, final String password)
      throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, java.security.cert.CertificateException {
    // Get the private key
    FileReader reader = new FileReader(keyFile);

    PEMParser pem = new PEMParser(reader);
    PEMKeyPair pemKeyPair = ((PEMKeyPair) pem.readObject());
    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter().setProvider("SC");
    KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);

    PrivateKey key = keyPair.getPrivate();

    pem.close();
    reader.close();

    // Get the certificate
    reader = new FileReader(cerFile);
    pem = new PEMParser(reader);

    X509CertificateHolder certHolder = (X509CertificateHolder) pem.readObject();
    java.security.cert.Certificate X509Certificate =
        new JcaX509CertificateConverter().setProvider("SC")
            .getCertificate(certHolder);

    pem.close();
    reader.close();

    // Put them into a PKCS12 keystore and write it to a byte[]
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null);
    ks.setKeyEntry("alias", (Key) key, password.toCharArray(),
        new java.security.cert.Certificate[]{X509Certificate});
    ks.store(bos, password.toCharArray());
    bos.close();
    return bos.toByteArray();
  }
}