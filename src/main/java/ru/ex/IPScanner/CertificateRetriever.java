package ru.ex.IPScanner;

import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.jetbrains.annotations.Nullable;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Class for obtaining server certificates {@link X509Certificate}.
 */
@Slf4j
public class CertificateRetriever {

    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    private final String ipAddress;

    /**
     * @param ipAddress IP Address for scanning for SSL Certificate
     */
    public CertificateRetriever(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    @Nullable
    public List<String> retrieveAlternativeNamesFromCertificate() {
        // create http response certificate interceptor
        HttpResponseInterceptor certificateInterceptor = CertificateRetriever::addCertificatesToContext;

        // creates an SSLContext object that trusts all certificates.
        SSLContext sslContext;
        try {
            String protocol = "TLS";
            sslContext = SSLContext.getInstance(protocol);
        } catch (NoSuchAlgorithmException e) {
            log.error("No implementation for such protocol: " + e.getLocalizedMessage());
            return null;
        }
        // creates an SSLConnectionSocketFactory object using the SSLContext
        // and sets it as the socket factory for the CloseableHttpClient.
        try {
            sslContext.init(null, new TrustManager[]
                    {new CustomX509TrustManager()},
                    new SecureRandom());
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);

        // create closable http client and assign the certificate interceptor
        try (CloseableHttpClient httpClient = HttpClients
                .custom()
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectTimeout(1000)
                        .setSocketTimeout(1000)
                        .build())
                .addInterceptorLast(certificateInterceptor)
                .setSSLSocketFactory(sslSocketFactory)
                .build()) {

            // make HTTP GET request to resource server
            HttpGet httpget = new HttpGet("https://" + ipAddress);
            log.info("Executing request " + httpget.getRequestLine());

            // create http context where the certificate will be added
            HttpContext context = new BasicHttpContext();
            httpClient.execute(httpget, context);

            // obtain the server certificates from the context
            Certificate[] peerCertificates = (Certificate[]) context.getAttribute(PEER_CERTIFICATES);

            // loop over certificates and get certificate data
            List<String> alternativeNames = new ArrayList<>();
            for (Certificate certificate : peerCertificates) {
                X509Certificate x509Cert = (X509Certificate) certificate;
                List<String> domains = x509Cert.getSubjectAlternativeNames()
                        .stream()
                        .map(list -> list.get(1).toString())
                        .collect(Collectors.toList());
                alternativeNames.addAll(domains);
                return alternativeNames;
            }

        } catch (IOException e) {
            log.error("I/O Exception: " + e.getLocalizedMessage());
        } catch (CertificateParsingException e) {
            log.error("Certificate Parsing Exception: " + e.getLocalizedMessage());
        }
        return null;
    }

    private static void addCertificatesToContext(HttpResponse httpResponse, HttpContext context)
            throws SSLPeerUnverifiedException {
        ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection)
                context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
        SSLSession sslSession = routedConnection.getSSLSession();

        if (sslSession != null) {

            // get the server certificates from the {@Link SSLSession}
            Certificate[] certificates = sslSession.getPeerCertificates();

            // add the certificates to the context, where we can later grab it from
            context.setAttribute(PEER_CERTIFICATES, certificates);
        }
    }
}