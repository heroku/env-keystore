package com.heroku.sdk;

import java.io.*;
import java.net.InetSocketAddress;
import java.lang.*;
import java.net.URL;
import com.sun.net.httpserver.HttpsServer;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import com.sun.net.httpserver.*;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URLConnection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

import java.net.InetAddress;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsExchange;

public class SimpleHTTPServer {

  public static class MyHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange t) throws IOException {
      String response = "This is the response";
      HttpsExchange httpsExchange = (HttpsExchange) t;
      t.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
      t.sendResponseHeaders(200, response.length());
      OutputStream os = t.getResponseBody();
      os.write(response.getBytes());
      os.close();
    }
  }

  /**
   * @param port
   */
  public void start(int port) throws Exception {

    try {
      // setup the socket address
      InetSocketAddress address = new InetSocketAddress(port);

      // initialise the HTTPS server
      HttpsServer httpsServer = HttpsServer.create(address, 0);
      SSLContext sslContext = SSLContext.getInstance("TLS");

      // initialise the keystore
      char[] password = "changeme".toCharArray();
      KeyStore ks = KeyStore.getInstance("JKS");
      FileInputStream fis = new FileInputStream("server.keystore");
      ks.load(fis, password);

      // setup the key manager factory
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      kmf.init(ks, password);

      // setup the trust manager factory
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
      tmf.init(ks);

      // setup the HTTPS context and parameters
      sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
      httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
        public void configure(HttpsParameters params) {
          try {
            // initialise the SSL context
            SSLContext c = SSLContext.getDefault();
            SSLEngine engine = c.createSSLEngine();
            params.setNeedClientAuth(false);
            params.setCipherSuites(engine.getEnabledCipherSuites());
            params.setProtocols(engine.getEnabledProtocols());

            // get the default parameters
            SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
            params.setSSLParameters(defaultSSLParameters);

          } catch (Exception ex) {
            System.out.println("Failed to create HTTPS port");
          }
        }
      });
      httpsServer.createContext("/", new MyHandler());
      httpsServer.setExecutor(null); // creates a default executor
      httpsServer.start();

    } catch (Exception exception) {
      System.out.println("Failed to create HTTPS server on port " + port + " of localhost");
      exception.printStackTrace();

    }
  }

}
