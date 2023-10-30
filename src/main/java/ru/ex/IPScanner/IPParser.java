package ru.ex.IPScanner;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class IPParser {

    public static List<String> parseIPAddressRange(String ipAddressRange) {
        String[] parts = ipAddressRange.split("/");
        if (parts.length != 2) {
            log.warn("Invalid IP address range: " + ipAddressRange);
            throw new IllegalArgumentException("Invalid IP address range: " + ipAddressRange);
        }
        String[] ipParts = parts[0].split("\\.");
        if (ipParts.length != 4) {
            log.warn("Invalid IP address range: " + ipAddressRange);
            throw new IllegalArgumentException("Invalid IP address range: " + ipAddressRange);
        }
        int maskBits = Integer.parseInt(parts[1]);
        if (maskBits < 0 || maskBits > 32) {
            log.warn("Invalid mask bits: " + maskBits);
            throw new IllegalArgumentException("Invalid mask bits: " + maskBits);
        }
        int ipInt = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(ipParts[i]);
            if (octet < 0 || octet > 255) {
                log.warn("Invalid IP address range: " + ipAddressRange);
                throw new IllegalArgumentException("Invalid IP address range: " + ipAddressRange);
            }
            ipInt |= octet << ((3 - i) * 8);
        }
        return getIpAddresses(ipAddressRange, maskBits, ipInt);
    }

    @NotNull
    private static List<String> getIpAddresses(String ipAddressRange, int maskBits, int ipInt) {
        int numIPs = 1 << (32 - maskBits);
        if (numIPs < 0) {
            log.warn("Invalid IP address range: " + ipAddressRange);
            throw new IllegalArgumentException("Invalid IP address range: " + ipAddressRange);
        }
        List<String> ipAddresses = new ArrayList<>();
        for (int i = 0; i < numIPs; i++) {
            int ipIntCurr = ipInt + i;
            String ipAddressCurr = ((ipIntCurr >> 24) & 0xFF) + "." +
                    ((ipIntCurr >> 16) & 0xFF) + "." +
                    ((ipIntCurr >> 8) & 0xFF) + "." +
                    (ipIntCurr & 0xFF);
            ipAddresses.add(ipAddressCurr);
        }
        return ipAddresses;
    }


    public static List<List<String>> divideList(List<String> list, int numParts) {
        if (list == null || list.isEmpty()) {
            log.warn("Invalid List: " + list);
            throw new IllegalArgumentException("Invalid List: " + list);
        }
        if (numParts <= 0) {
            log.warn("Invalid number of parts: " + numParts);
            throw new IllegalArgumentException("Invalid number of parts: " + numParts);
        }
        List<List<String>> parts = new ArrayList<>();
        int size = list.size();
        int chunkSize = size / numParts;
        int leftOverSize = size % numParts;
        int index = 0;
        for (int i = 0; i < numParts; i++) {
            int currChunkSize = chunkSize;
            if (leftOverSize > 0) {
                currChunkSize++;
                leftOverSize--;
            }
            List<String> partList = list.subList(index, index + currChunkSize);
            parts.add(partList);
            index += currChunkSize;
        }
        return parts;
    }

}
