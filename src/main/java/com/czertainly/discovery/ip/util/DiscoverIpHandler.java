package com.czertainly.discovery.ip.util;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.discovery.ip.enums.DiscoveryKind;
import com.czertainly.discovery.ip.service.impl.AttributeServiceImpl;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;
import org.apache.commons.net.util.SubnetUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;

public class DiscoverIpHandler {
    private static final Logger logger = LoggerFactory.getLogger(DiscoverIpHandler.class);

    private DiscoverIpHandler() {
        throw new IllegalStateException("Utility Class");
    }

    public static Set<String> getAllIp(DiscoveryRequestDto request) {
        logger.debug("Discovering the IP");

        DiscoveryKind kind = DiscoveryKind.findByCode(request.getKind());

        String ports = AttributeServiceImpl.getPortDataAttributeContentValue(request.getAttributes());
        Boolean allPorts = AttributeServiceImpl.getAllPortsDataAttributeContentValue(request.getAttributes());

        Set<String> ipsOrHostnames;

        if (kind.equals(DiscoveryKind.IP_Hostname)) {
            String ips = AttributeServiceImpl.getDiscoveryIpDataAttributeContentValue(request.getAttributes());
            ipsOrHostnames = getIpHostnameUrls(ips);
        } else {
            throw new IllegalArgumentException("Unknown kind");
        }

        return buildUrls(ipsOrHostnames, getPorts(ports, allPorts));
    }

    public static Set<String> getIpHostnameUrls(String ips) {
        // get all IP addresses and hostnames from comma separated string
        // use a Set to avoid duplicate values
        Set<String> ipsHostname = new HashSet<>();

        for (String indIp : ips.split(",")) {
            if (Pattern.compile(AttributeServiceImpl.HOSTNAME_VALIDATION_REGEX).matcher(indIp).matches()) {
                ipsHostname.add(indIp);
            } else if (Pattern.compile(AttributeServiceImpl.IP_ADDRESS_VALIDATION_REGEX).matcher(indIp).matches()) {
                ipsHostname.add(indIp);
            } else if (Pattern.compile(AttributeServiceImpl.IP_ADDRESS_RANGE_VALIDATION_REGEX).matcher(indIp).matches()) {
                String[] ipRange = indIp.split("-");
                ipsHostname.addAll(getIpRange(ipRange[0], ipRange[1]));
            } else if (Pattern.compile(AttributeServiceImpl.IP_SUBNET_VALIDATION_REGEX).matcher(indIp).matches()) {
                SubnetUtils utils = new SubnetUtils(indIp);
                ipsHostname.addAll(Arrays.asList(utils.getInfo().getAllAddresses()));
            } else {
                logger.error("Invalid input format for IP address, hostname, range, or subnet: {}", indIp);
                throw new ValidationException("Invalid input format for IP address, hostname, range, or subnet: " + indIp);
            }
        }

        return ipsHostname;
    }

    public static Set<String> getIpRange(String startIpAddress, String endIpAddress) {
        // get all IP addresses in defined range
        Set<String> ipsHostname = new HashSet<>();
        IPAddress lower;
        IPAddress upper;
        try {
            lower = new IPAddressString(startIpAddress).toAddress();
            upper = new IPAddressString(endIpAddress).toAddress();
        } catch (AddressStringException e) {
            logger.error("Error in IP address range", e);
            throw new ValidationException("Error in IP address range");
        }
        IPAddressSeqRange range = lower.spanWithRange(upper);

        for (IPAddress address : range.getIterable()) {
            ipsHostname.add(address.toString());
        }

        return ipsHostname;
    }

    /**
     * Get ports from a comma separated string of ports or all ports
     *
     * @param ports    comma separated string of ports
     * @param allPorts boolean value to get all ports
     * @return set of ports
     */
    public static Set<String> getPorts(String ports, Boolean allPorts) {
        // get all ports or ports from a comma separated string
        // use a Set to avoid duplicate values
        Set<String> portNumbers = new HashSet<>();

        if (Boolean.TRUE.equals(allPorts)) {
            for (int i = 0; i < 65535; i++) {
                portNumbers.add(String.valueOf(i));
            }
        } else {
            for (String port : ports.split(",")) {
                if (Pattern.compile(AttributeServiceImpl.PORT_VALIDATION_REGEX).matcher(port).matches()) {
                    portNumbers.add(port);
                } else if (Pattern.compile(AttributeServiceImpl.PORT_RANGE_VALIDATION_REGEX).matcher(port).matches()) {
                    String[] portRange = port.split("-");
                    int start = Integer.parseInt(portRange[0]);
                    int end = Integer.parseInt(portRange[1]);
                    for (int i = start; i <= end; i++) {
                        portNumbers.add(String.valueOf(i));
                    }
                } else {
                    throw new IllegalArgumentException("Invalid input format for port: " + port);
                }
            }
        }

        return portNumbers;
    }

    /**
     * Build URLs for all IP addresses in range with defined ports
     * @param ipsInRange set of IP addresses in range
     * @param applicablePorts set of ports
     * @return set of URLs
     */
    public static Set<String> buildUrls(Set<String> ipsInRange, Set<String> applicablePorts) {
        Set<String> urls = new TreeSet<>();
        for (String ip : ipsInRange) {
            for (String port : applicablePorts) {
                urls.add("https://" + ip + ":" + port);
            }
        }
        return urls;
    }
}