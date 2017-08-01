package com.heroku.sdk;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;

public class InvokeSelfSignedServiceTest {
  public void testInvokeSelfSignedService() throws Exception {
    String certUrlStr = "http://www.selfsigned.xyz/server.crt";
    URL certUrl = new URL(certUrlStr);
    HttpURLConnection con = (HttpURLConnection) certUrl.openConnection();
    con.setDoInput(true);
    con.setRequestMethod("GET");

    String cert = readStream(con.getInputStream());

    assert cert != null : "Certificate is null";
    assert cert.startsWith("-----BEGIN CERTIFICATE-----") : "Certificate is malformed";

    enableTrustStore(cert);

    String urlStr = "https://ssl.selfsigned.xyz";
    URL url = new URL(urlStr);
    HttpsURLConnection httpsConn = (HttpsURLConnection)url.openConnection();
    httpsConn.setDoInput(true);
    httpsConn.setRequestMethod("GET");

    String response = readStream(httpsConn.getInputStream());

    assert response.contains("Self-Signed SSL Certificate Example") : "Could not invoked HTTPS service.";
  }

  private void enableTrustStore(String trustedCert)
      throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, KeyManagementException {

    KeyStore ts = new EnvKeyStore(trustedCert, "password").keyStore();

    String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(ts);

    SSLContext sc = SSLContext.getInstance("TLS");
    sc.init(null, tmf.getTrustManagers(), new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
  }

  private static String readStream(InputStream is) throws Exception {
    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
    String output = "";
    String tmp = reader.readLine();
    while (tmp != null) {
      output += tmp + "\n";
      tmp = reader.readLine();
    }
    return output;
  }
}
