package ru.ex.Export;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

@Slf4j
public class ExporterToFile implements IPExporter{
    @Override
    public void saveDomainsToFile(List<String> domains) {
        log.info("Trying to initialize BufferedWriter");
        if (domains == null || domains.isEmpty())
            return;
        try (BufferedWriter writer =
                     new BufferedWriter(new FileWriter("src/main/resources/domains.txt", true))) {
            for (String domain : domains) {
                if(domain != null && !domain.isEmpty())
                    writer.write(domain + "\n");
            }
        } catch (IOException e) {
            log.error("I/O Exception while saving domains to file: " + e.getLocalizedMessage());
        }
    }
}
