# EnvKeyStore [![Build Status](https://travis-ci.org/jkutner/env-keystore.svg?branch=master)](https://travis-ci.org/jkutner/env-keystore)

A Java library to create
[KeyStore](http://docs.oracle.com/javase/8/docs/api/java/security/KeyStore.html)
and TrustStore objects in memory from environment variables.

## Usage

Include this library in your application as a Maven depenency:

```xml
<dependency>
  <groupId>com.github.jkutner</groupId>
  <artifactId>env-keystore</artifactId>
  <version>0.1.0</version>
</dependency>
```

### Creating a TrustStore

Creating a TrustStore requires that the certificate PEM be set as an environment variable.
You pass that environment variable name to the `EnvKeyStore.create` method:

```java
KeyStore ts = EnvKeyStore.create("TRUSTED_CERT").keyStore();
```

You can use the KeyStore like any other. For example, you might invoke a service with the trusted cert:

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(ts);

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, tmf.getTrustManagers(), new SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

String urlStr = "https://ssl.selfsigned.xyz";
URL url = new URL(urlStr);
HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
con.setDoInput(true);
con.setRequestMethod("GET");
con.getInputStream().close();
```

### Creating a KeyStore

Creating a KeyStore requires that the key, certificate and password are all set as environment variables.
You pass the environment variable names to the `EnvKeyStore.create` method:

```java
KeyStore ks = EnvKeyStore.create("KEYSTORE_KEY", "KEYSTORE_CERT", "KEYSTORE_PASSWORD").keyStore();
```

You can use the KeyStore like any other. But you might also want to convert it to an input stream.
For example, you might start a [Ratpack](https://ratpack.io) server:

```java
EnvKeyStore eks = EnvKeyStore.create("KEYSTORE_KEY", "KEYSTORE_CERT", "KEYSTORE_PASSWORD");

RatpackServer.start(s -> s
  .serverConfig(c -> {
    c.ssl(SSLContexts.sslContext(eks.toInputStream(), eks.password()));
  })
  .handlers(chain -> chain
    .all(ctx -> ctx.render("Hello!"))
  )
);
```
