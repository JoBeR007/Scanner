package ru.ex;

import io.javalin.Javalin;
import io.javalin.util.FileUtil;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import ru.ex.Export.ExporterToFile;
import ru.ex.IPScanner.CertificateRetriever;

import java.util.ArrayList;
import java.util.List;

import static ru.ex.IPScanner.IPParser.divideList;
import static ru.ex.IPScanner.IPParser.parseIPAddressRange;

@Slf4j
public class Main {

    public static void main(String[] args) {
        log.info("Starting application");
        Javalin app = Javalin.create().start(7000);

        app.get("/", ctx ->
                ctx.html(FileUtil.readFile("src/main/resources/public/index.html")));

        app.post("/scan", ctx -> {
            String ipRange = ctx.formParam("ip-address");
            String threadsStr = ctx.formParam("num-threads");
            assert ipRange != null;
            assert threadsStr != null;
            int numThreads = Integer.parseInt(threadsStr);

            ctx.html("<div class=\"spinner-border\" role=\"status\">\n" +
                    "  <span class=\"sr-only\">Loading...</span>\n" +
                    "</div>");

            List<String> ipAddresses = parseIPAddressRange(ipRange);
            List<List<String>> ipAddressParts = divideList(ipAddresses, numThreads);
            List<Thread> threads = retrieveInThreads(ipAddressParts);

            for (Thread thread : threads) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    log.error("Thread interrupted: " + e.getLocalizedMessage());
                }
            }
            ctx.html(FileUtil.readFile("src/main/resources/domains.txt"));
        });

        app.exception(IllegalArgumentException.class, (e, ctx) -> {
            ctx.status(500);
            ctx.result("Please, check your input: " + e.getLocalizedMessage());
        });

        app.exception(Exception.class, (e, ctx) -> {
            ctx.status(500);
            ctx.result(e.getLocalizedMessage());
        });

    }

    @NotNull
    private static List<Thread> retrieveInThreads(List<List<String>> ipAddressParts) {
        List<Thread> threads = new ArrayList<>();

        for (List<String> ipAddressPart : ipAddressParts){
            Thread thread = new Thread(() -> {
                for (String ipAddress : ipAddressPart) {
                    CertificateRetriever cr = new CertificateRetriever(ipAddress);
                    List<String> domains = cr.retrieveAlternativeNamesFromCertificate();
                    if (domains != null && !domains.isEmpty())
                        new ExporterToFile().saveDomainsToFile(domains);
                }
            });
            thread.start();
            threads.add(thread);
        }
        return threads;
    }
}