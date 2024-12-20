package com.czertainly.discovery.ip.service.impl;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.connector.AttributesController;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.InfoAttribute;
import com.czertainly.api.model.common.attribute.v2.constraint.RangeAttributeConstraint;
import com.czertainly.api.model.common.attribute.v2.constraint.RegexpAttributeConstraint;
import com.czertainly.api.model.common.attribute.v2.constraint.data.RangeAttributeConstraintData;
import com.czertainly.api.model.common.attribute.v2.content.*;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.properties.InfoAttributeProperties;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.discovery.ip.enums.DiscoveryKind;
import com.czertainly.discovery.ip.service.AttributeService;
import com.czertainly.discovery.ip.util.DiscoverIpHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class AttributeServiceImpl implements AttributeService {

    private static final Logger logger = LoggerFactory.getLogger(AttributesController.class);

    public static final String IP_ADDRESS_VALIDATION_REGEX = "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$";
    public static final String IP_ADDRESS_RANGE_VALIDATION_REGEX =
            "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}-((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$";
    public static final String HOSTNAME_VALIDATION_REGEX =
            "^(?=.{4,253}$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63})$";
    public static final String IP_SUBNET_VALIDATION_REGEX = "^([0-9]{1,3}\\.){3}[0-9]{1,3}($|/([1-9]|[12][0-9]|3[012]))$";

    // Combining the patterns into one
    public static final String COMBINED_IP_HOSTNAME_VALIDATION_REGEX =
            "^" +
                    "(?:" +
                    IP_ADDRESS_VALIDATION_REGEX.substring(1, IP_ADDRESS_VALIDATION_REGEX.length() - 1) + "|" +
                    IP_ADDRESS_RANGE_VALIDATION_REGEX.substring(1, IP_ADDRESS_RANGE_VALIDATION_REGEX.length() - 1) + "|" +
                    HOSTNAME_VALIDATION_REGEX.substring(1, HOSTNAME_VALIDATION_REGEX.length() - 1) + "|" +
                    IP_SUBNET_VALIDATION_REGEX.substring(1, IP_SUBNET_VALIDATION_REGEX.length() - 1) +
                    ")" +
                    "(?:," +
                    "(?:" +
                    IP_ADDRESS_VALIDATION_REGEX.substring(1, IP_ADDRESS_VALIDATION_REGEX.length() - 1) + "|" +
                    IP_ADDRESS_RANGE_VALIDATION_REGEX.substring(1, IP_ADDRESS_RANGE_VALIDATION_REGEX.length() - 1) + "|" +
                    HOSTNAME_VALIDATION_REGEX.substring(1, HOSTNAME_VALIDATION_REGEX.length() - 1) + "|" +
                    IP_SUBNET_VALIDATION_REGEX.substring(1, IP_SUBNET_VALIDATION_REGEX.length() - 1) +
                    ")" +
                    ")*" +
                    "$";

    public static final String PORT_VALIDATION_REGEX = "^(6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3})$";
    public static final String PORT_RANGE_VALIDATION_REGEX =
            "^" +
                    PORT_VALIDATION_REGEX.substring(1, PORT_VALIDATION_REGEX.length() - 1) + "-" +
                    PORT_VALIDATION_REGEX.substring(1, PORT_VALIDATION_REGEX.length() - 1) +
                    "$";

    // Combining the patterns into one
    public static final String COMBINED_PORT_VALIDATION_REGEX =
            "^(" +
                    PORT_VALIDATION_REGEX.substring(1, PORT_VALIDATION_REGEX.length() - 1) +
                    "|" +
                    PORT_RANGE_VALIDATION_REGEX.substring(1, PORT_RANGE_VALIDATION_REGEX.length() - 1) +
                    ")(,(" +
                    PORT_VALIDATION_REGEX.substring(1, PORT_VALIDATION_REGEX.length() - 1) +
                    "|" +
                    PORT_RANGE_VALIDATION_REGEX.substring(1, PORT_RANGE_VALIDATION_REGEX.length() - 1) +
                    "))*$";

    public static final String INFO_ATTRIBUTE_IP_HOSTNAME_UUID = "900a9da3-d7e3-4771-bdec-809f507731f1";
    public static final String INFO_ATTRIBUTE_IP_HOSTNAME_NAME = "info_ipHostname";
    public static final String INFO_ATTRIBUTE_IP_HOSTNAME_DESCRIPTION = "IPs/Hostnames certificates to be discovered.";
    public static final String INFO_ATTRIBUTE_IP_HOSTNAME_LABEL = "IPs/Hostnames certificates to be discovered";

    public static final String DATA_ATTRIBUTE_DISCOVERY_IP_UUID = "1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac";
    public static final String DATA_ATTRIBUTE_DISCOVERY_IP_NAME = "ip";
    public static final String DATA_ATTRIBUTE_DISCOVERY_IP_DESCRIPTION = "Multiple values can be given seperated by comma ','. "
            + "IP address, hostname, IP address range, and CIDR subnet are supported.";
    public static final String DATA_ATTRIBUTE_DISCOVERY_IP_LABEL = "IPs/Hostnames";

    public static final String DATA_ATTRIBUTE_PORT_UUID = "a9091e0d-f9b9-4514-b275-1dd52aa870ec";
    public static final String DATA_ATTRIBUTE_PORT_NAME = "port";
    public static final String DATA_ATTRIBUTE_PORT_DESCRIPTION = "Multiple values can be given separated by comma ','. "
            + "Port number or range of port numbers are supported.";
    public static final String DATA_ATTRIBUTE_PORT_LABEL = "Ports";
    public static final StringAttributeContent DATA_ATTRIBUTE_PORT_DEFAULT_CONTENT = new StringAttributeContent("443", "443");

    public static final String DATA_ATTRIBUTE_ALL_PORTS_UUID = "3c70d728-e8c3-40f9-b9b2-5d7256f89ef0";
    public static final String DATA_ATTRIBUTE_ALL_PORTS_NAME = "allPorts";
    public static final String DATA_ATTRIBUTE_ALL_PORTS_DESCRIPTION = "Check to discover certificates from all ports.";
    public static final String DATA_ATTRIBUTE_ALL_PORTS_LABEL = "All Ports?";
    public static final BooleanAttributeContent DATA_ATTRIBUTE_ALL_PORTS_DEFAULT_CONTENT = new BooleanAttributeContent(false);

    public static final String DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_UUID = "1517c7a5-34cb-4f94-a0aa-1e9fe5b5b277";
    public static final String DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME = "data_parallel_executions";
    public static final String DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_DESCRIPTION = "Number of parallel executions of the discovery process. Default is 1 and maximum is 100.";
    public static final String DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_LABEL = "Number of parallel executions";
    public static final IntegerAttributeContent DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_DEFAULT_CONTENT =
            new IntegerAttributeContent(1);


    @Override
    public List<BaseAttribute> getAttributes(String kind) {
        logger.debug("Getting the attributes for {}", kind);

        List<BaseAttribute> attributes = new ArrayList<>();

        if (DiscoveryKind.IP_Hostname.getCode().equals(kind)) {
            attributes.add(createIpHostnameInfoAttribute());
            attributes.add(createDiscoveryIpDataAttribute());
            attributes.add(createPortDataAttribute());
            attributes.add(createAllPortsDataAttribute());
            attributes.add(createParallelExecutionsDataAttribute());
        } else {
            throw new IllegalArgumentException("Unsupported kind " + kind);
        }

        logger.debug("Attributes constructed. {}", attributes);
        return attributes;
    }

    private InfoAttribute createIpHostnameInfoAttribute() {
        InfoAttribute attribute = new InfoAttribute();
        attribute.setUuid(INFO_ATTRIBUTE_IP_HOSTNAME_UUID);
        attribute.setName(INFO_ATTRIBUTE_IP_HOSTNAME_NAME);
        attribute.setDescription(INFO_ATTRIBUTE_IP_HOSTNAME_DESCRIPTION);
        attribute.setType(AttributeType.INFO);
        attribute.setContentType(AttributeContentType.TEXT);
        InfoAttributeProperties ipHostnameProperties = new InfoAttributeProperties();
        ipHostnameProperties.setLabel(INFO_ATTRIBUTE_IP_HOSTNAME_LABEL);
        ipHostnameProperties.setVisible(true);
        attribute.setProperties(ipHostnameProperties);

        String content = """
                The IP-Hostname discovery is used to discover the certificates from the following sources:
                - IP address (`10.100.2.14`)
                - Hostname (`www.example.com`)
                - IP address range (`10.1.1.20-10.1.1.150`)
                - CIDR Subnet (`172.16.1.0/24`)

                By default, the discovery is done on port 443. If the certificates are hosted on a different port,
                the port numbers can be provided as input, the following is supported:
                - Single port number (`443`)
                - Range of port numbers (`9000-10000`)
                
                URLs for discovery are built as combination of provided IP addresses or hostnames and port numbers.
                Each URL is processed separately to discover the certificates.

                *The discovery can be done on all ports. However, it is recommended to provide the port numbers for better performance
                and avoiding network issues.*
                
                By default, each URL is processed sequentially. The number of parallel executions can be increased
                to improve the performance. The maximum number of parallel executions that can be set is `1000`.
                """;

        attribute.setContent(List.of(new TextAttributeContent(content)));

        return attribute;
    }

    private DataAttribute createDiscoveryIpDataAttribute() {
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(DATA_ATTRIBUTE_DISCOVERY_IP_UUID);
        attribute.setName(DATA_ATTRIBUTE_DISCOVERY_IP_NAME);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties ipProperties = new DataAttributeProperties();
        ipProperties.setLabel(DATA_ATTRIBUTE_DISCOVERY_IP_LABEL);
        ipProperties.setRequired(true);
        ipProperties.setReadOnly(false);
        ipProperties.setVisible(true);
        ipProperties.setList(false);
        ipProperties.setMultiSelect(false);
        attribute.setDescription(DATA_ATTRIBUTE_DISCOVERY_IP_DESCRIPTION);
        attribute.setProperties(ipProperties);

        // create restrictions
        RegexpAttributeConstraint regexpAttributeConstraint = new RegexpAttributeConstraint();
        regexpAttributeConstraint.setDescription("IP/Hostname format");
        regexpAttributeConstraint.setErrorMessage("Invalid IP/Hostname format");
        regexpAttributeConstraint.setData(COMBINED_IP_HOSTNAME_VALIDATION_REGEX);
        attribute.setConstraints(List.of(regexpAttributeConstraint));

        return attribute;
    }

    private DataAttribute createPortDataAttribute() {
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(DATA_ATTRIBUTE_PORT_UUID);
        attribute.setName(DATA_ATTRIBUTE_PORT_NAME);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties portProperties = new DataAttributeProperties();
        portProperties.setLabel(DATA_ATTRIBUTE_PORT_LABEL);
        portProperties.setRequired(false);
        portProperties.setReadOnly(false);
        portProperties.setVisible(true);
        portProperties.setList(false);
        portProperties.setMultiSelect(false);
        attribute.setContent(List.of(DATA_ATTRIBUTE_PORT_DEFAULT_CONTENT));
        attribute.setDescription(DATA_ATTRIBUTE_PORT_DESCRIPTION);
        attribute.setProperties(portProperties);
        return attribute;
    }

    private DataAttribute createAllPortsDataAttribute() {
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(DATA_ATTRIBUTE_ALL_PORTS_UUID);
        attribute.setName(DATA_ATTRIBUTE_ALL_PORTS_NAME);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);
        DataAttributeProperties allPortProperties = new DataAttributeProperties();
        allPortProperties.setLabel(DATA_ATTRIBUTE_ALL_PORTS_LABEL);
        allPortProperties.setRequired(false);
        allPortProperties.setReadOnly(false);
        allPortProperties.setVisible(true);
        allPortProperties.setList(false);
        allPortProperties.setMultiSelect(false);
        attribute.setProperties(allPortProperties);
        attribute.setContent(List.of(DATA_ATTRIBUTE_ALL_PORTS_DEFAULT_CONTENT));
        attribute.setDescription(DATA_ATTRIBUTE_ALL_PORTS_DESCRIPTION);
        return attribute;
    }

    private DataAttribute createParallelExecutionsDataAttribute() {
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_UUID);
        attribute.setName(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        DataAttributeProperties parallelExecutionsProperties = new DataAttributeProperties();
        parallelExecutionsProperties.setLabel(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_LABEL);
        parallelExecutionsProperties.setRequired(false);
        parallelExecutionsProperties.setReadOnly(false);
        parallelExecutionsProperties.setVisible(true);
        parallelExecutionsProperties.setList(false);
        parallelExecutionsProperties.setMultiSelect(false);
        attribute.setProperties(parallelExecutionsProperties);
        attribute.setContent(List.of(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_DEFAULT_CONTENT));
        attribute.setDescription(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_DESCRIPTION);

        // create restrictions
        RangeAttributeConstraint rangeAttributeConstraint = new RangeAttributeConstraint();
        RangeAttributeConstraintData rangeData = new RangeAttributeConstraintData();
        rangeData.setFrom(1);
        rangeData.setTo(100);
        rangeAttributeConstraint.setData(rangeData);
        rangeAttributeConstraint.setDescription("Allowed values for parallel executions");
        rangeAttributeConstraint.setErrorMessage("Invalid value for parallel executions, it can be between 1 and 100");

        attribute.setConstraints(List.of(rangeAttributeConstraint));

        return attribute;
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttributeDto> attributes) {
        validateKind(kind);
        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);

        validateIpHostnameDataAttributeContentValue(attributes);

        return true;
    }

    private void validateKind(String kind) {
        // check if the kind is one of supported values from enum class Kind
        DiscoveryKind.findByCode(kind);
    }

    private void validateIpHostnameDataAttributeContentValue(List<RequestAttributeDto> attributes) {
        StringAttributeContent content = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                DATA_ATTRIBUTE_DISCOVERY_IP_NAME, attributes, StringAttributeContent.class);

        if (content == null || content.getData() == null) {
            throw new ValidationException("Discovery IPs/Hostname is required, but was not provided");
        }

        DiscoverIpHandler.getIpHostnameUrls(content.getData());
    }

    public static String getDiscoveryIpDataAttributeContentValue(List<RequestAttributeDto> attributes) {
        StringAttributeContent content = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                DATA_ATTRIBUTE_DISCOVERY_IP_NAME, attributes, StringAttributeContent.class);

        if (content != null && content.getData() != null) {
            return content.getData();
        }

        throw new ValidationException("Discovery IPs/Hostname is required, but was not provided");
    }

    public static String getPortDataAttributeContentValue(List<RequestAttributeDto> attributes) {
        StringAttributeContent content = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                DATA_ATTRIBUTE_PORT_NAME, attributes, StringAttributeContent.class);

        if (content != null && content.getData() != null) {
            return content.getData();
        }

        return DATA_ATTRIBUTE_PORT_DEFAULT_CONTENT.getData();
    }

    public static Boolean getAllPortsDataAttributeContentValue(List<RequestAttributeDto> attributes) {
        BooleanAttributeContent content = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                DATA_ATTRIBUTE_ALL_PORTS_NAME, attributes, BooleanAttributeContent.class);

        if (content != null && content.getData() != null) {
            return content.getData();
        }

        return DATA_ATTRIBUTE_ALL_PORTS_DEFAULT_CONTENT.getData();
    }

    public static Integer getParallelExecutionsDataAttributeContentValue(List<RequestAttributeDto> attributes) {
        IntegerAttributeContent content = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME, attributes, IntegerAttributeContent.class);

        if (content != null && content.getData() != null) {
            return content.getData();
        }

        return DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_DEFAULT_CONTENT.getData();
    }

}
