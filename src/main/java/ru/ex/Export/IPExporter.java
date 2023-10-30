package ru.ex.Export;

import java.util.List;

public interface IPExporter {
    void saveDomainsToFile(List<String> domains);
}
