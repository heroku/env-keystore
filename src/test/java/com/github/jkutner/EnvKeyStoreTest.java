package com.github.jkutner;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class EnvKeyStoreTest {

  private static final String CERT = "-----BEGIN CERTIFICATE-----\n" +
      "MIIDQjCCAioCCQDG7inQ3G12+zANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJV\n" +
      "UzEQMA4GA1UECBMHQWxhYmFtYTETMBEGA1UEBxMKSHVudHN2aWxsZTEhMB8GA1UE\n" +
      "ChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQowCAYDVQQDFAEqMB4XDTE2MDUx\n" +
      "MzEzNTI0MFoXDTE3MDUxMzEzNTI0MFowYzELMAkGA1UEBhMCVVMxEDAOBgNVBAgT\n" +
      "B0FsYWJhbWExEzARBgNVBAcTCkh1bnRzdmlsbGUxITAfBgNVBAoTGEludGVybmV0\n" +
      "IFdpZGdpdHMgUHR5IEx0ZDEKMAgGA1UEAxQBKjCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
      "ggEPADCCAQoCggEBAMzSZ9UA9MzwgDUjPbLblLf+JXy8SEwgVinxxXmVw14V/BFW\n" +
      "QY63Q1ViTLjRei4vAgSRHbwF1URnmXHf2tW81DulaNWddu6MbXFtpnOD5Q66e/BY\n" +
      "X3a4KyoYMbJAGwtM7Eg2biiWNt8EzjTTOoO8bQFz9A8W5ILI2cDYVMdYiOM8HY6G\n" +
      "JGgFKcQ+S+5/mki92stDKcQfJA8BTU6y00jmszjAE8OLs4nwT48mZBVqq0mNmjxS\n" +
      "RwkMrtQnDfgInKsBJI9iSCBp+G+viaiLFJDUQh7HM56LiZ7lmAWj35HyKhNY61uY\n" +
      "UDZM+OO9rYXFz/4irg0xBYdyN3GBje3RDjxpzecCAwEAATANBgkqhkiG9w0BAQUF\n" +
      "AAOCAQEAtoYTKCZXr45vtVxtsCtWh001cUwGWga1L+WNaGCJcZgV0QRyeDrEXClF\n" +
      "M29GMLpYHViDpCJmoYh5CFl1vGUxdzp0ovOgESuQJtCK8SGZ9mAdgP08C4PhJikQ\n" +
      "i3gnwzfFjfdJ1VdIQ5AV7PEgpViSyfNb8u8XPqQgfHQQ6BCACxNNPEx5OIFv63Tx\n" +
      "ewhP6q1cswzjhZBNltWwGFN8/k8KYg5s94/KYksDo3hzy6pH9EHb4F/ZuQ+P8HOw\n" +
      "5n1NdCnB9Z/GEMmXtKg5j9Ww1vbYCI110Sp2Bmj421H6s2yMoL22ZGXhV41H3BoJ\n" +
      "Eb8Ileh6ORO5Hh9zhiftRMIl80x0cQ==\n" +
      "-----END CERTIFICATE-----\n" +
      "";

  private static final String KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEpQIBAAKCAQEAzNJn1QD0zPCANSM9stuUt/4lfLxITCBWKfHFeZXDXhX8EVZB\n" +
      "jrdDVWJMuNF6Li8CBJEdvAXVRGeZcd/a1bzUO6Vo1Z127oxtcW2mc4PlDrp78Fhf\n" +
      "drgrKhgxskAbC0zsSDZuKJY23wTONNM6g7xtAXP0DxbkgsjZwNhUx1iI4zwdjoYk\n" +
      "aAUpxD5L7n+aSL3ay0MpxB8kDwFNTrLTSOazOMATw4uzifBPjyZkFWqrSY2aPFJH\n" +
      "CQyu1CcN+AicqwEkj2JIIGn4b6+JqIsUkNRCHscznouJnuWYBaPfkfIqE1jrW5hQ\n" +
      "Nkz4472thcXP/iKuDTEFh3I3cYGN7dEOPGnN5wIDAQABAoIBAColyfQNBFL/0oIc\n" +
      "xF9/y/SoubIXVJFFvjVXaRmB9ffwcjRnGYpyr8psNfl6Mbg7OCEUc5fzY1V2NB84\n" +
      "v2FoQAweF5qNkqG4B/VlaPEwXPxQ55wns01MzKUW4XMaufXzWFPrz3NOpe/ynzRD\n" +
      "mzDsn0nDQJ+ySEeZaSXD3n4++7w2jmiQNXvgV7CttBiSwJiXS6t2k3iNte0m7NaM\n" +
      "gEBzh907gtIHoj9NBfvLT44MX+tiOwrTREx61fhxluhbwbv/IEsxLahl7OSVt2gt\n" +
      "MbzhZZ3r/DnhI5QYd7iveSeKCIbOH1mRO43lZ5BaTSmPLseLfPTxKaBJP6m6WX6a\n" +
      "26xw90ECgYEA5cRtGP4eQOAy1JewQRQYcw8i94GCfl1hdZm2INHLLR+1V8zan6Xl\n" +
      "eg7NXx375hxZWbbvKcHU+hhacMiMeXf7+xjGvdGEqbd7RWyVa4Nld/Bp82unT0Gz\n" +
      "SSN6oRZURxy0ZQiqlggoN01vZ/UuKIwgVMetEQmZWDWYTQfDAHju6RECgYEA5DTh\n" +
      "6wcU5NjbRgRVTki7WB3hucZd9RnSrabDPY1SQ4e4/nMYafp0qCfACBeDxAEV6OCJ\n" +
      "Nc7/eIjIQqOlZ214a0oCJPLp6i2BX8yO2hoq5fwRWveGnahnpyGApKqOqUc7Dd2u\n" +
      "RBY1DbZQJChycRCy9ClrOpYDsqTsRHy7gw08B3cCgYEAn22WTbs1/soSOxUtxVpO\n" +
      "RLgCCT8h7tCYqWMIzukDU8ImsE+Cezg/bFwNAKzrdpXBIdEfThgi0Y5IYu2lGzu3\n" +
      "6lkcveU9ag3YSSm43CsGIxz8R10xcHskDeHCWzgFLnqqaViEFSp/zS+716R2bMge\n" +
      "PvV2DtZcQqqdjQWPtyoyjCECgYEAyEXsuqF1Yb06+oCVCOXlnFhlH++Jx6+I6CMB\n" +
      "F0SuHFvBK3WAyIkn1edErRVN6zb0rnJXmGR4aaTI80rAvzsgQjAqH5kbVgvnjVZt\n" +
      "S9VJLpr/9DBk8Hm5tcA+MMUJ/F9p4SpaZKCEoOsN/B2PCdEY7BRpaXn79sysGRLK\n" +
      "USHNO9MCgYEAw70iSniDtc4zumbqCCyn3xrpDFR2eL302wEE8AqPaHAl8+W5rAID\n" +
      "axO7ye3XhQ9+h8N7uPp57uy8G4lHmy+TwsvuQxKDXY3bU1x5D42UfXUsowlKAYyZ\n" +
      "O2bi6Ju9X04P7dsK8lpiSGk4+t1g/VJ909YrWs2a0xe7cW1fwZ4Mkss=\n" +
      "-----END RSA PRIVATE KEY-----\n" +
      "";

  private static final String PASSWORD = "password";

  public void testTrustStore()
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

    EnvKeyStore eks = new EnvKeyStore(CERT);

    assert eks.password() == null : "Password for trust cert was not null";

    assert eks.keyStore() != null : "TrustStore is null";

    assert eks.keyStore().size() == 1 : "TrustStore does not contain 1 entry (" + eks.keyStore().size() + ")";
  }

  public void testKeyStore()
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

    EnvKeyStore eks = new EnvKeyStore(KEY, CERT, PASSWORD);

    assert eks.password().equals(PASSWORD) : "Password for key store is incorrect";

    assert eks.keyStore() != null : "KeyStore is null";

    assert eks.keyStore().size() == 1 : "KeyStore does not contain 1 entry (" + eks.keyStore().size() + ")";
  }
}
