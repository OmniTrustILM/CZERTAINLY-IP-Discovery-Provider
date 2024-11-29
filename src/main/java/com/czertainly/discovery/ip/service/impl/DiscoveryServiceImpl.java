package com.czertainly.discovery.ip.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderDto;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.discovery.ip.dao.Certificate;
import com.czertainly.discovery.ip.dao.DiscoveryHistory;
import com.czertainly.discovery.ip.dto.ConnectionResponse;
import com.czertainly.discovery.ip.repository.CertificateRepository;
import com.czertainly.discovery.ip.service.ConnectionService;
import com.czertainly.discovery.ip.service.DiscoveryHistoryService;
import com.czertainly.discovery.ip.service.DiscoveryService;
import com.czertainly.discovery.ip.util.DiscoverIpHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@Transactional
public class DiscoveryServiceImpl implements DiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryServiceImpl.class);

    private PlatformTransactionManager transactionManager;

    private ConnectionService connectionService;
    private CertificateRepository certificateRepository;
    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setConnectionService(ConnectionService connectionService) {
        this.connectionService = connectionService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setDiscoveryHistoryService(DiscoveryHistoryService discoveryHistoryService) {
        this.discoveryHistoryService = discoveryHistoryService;
    }

    @Override
    public DiscoveryProviderDto getProviderDtoData(DiscoveryDataRequestDto request, DiscoveryHistory history) {
        DiscoveryProviderDto dto = new DiscoveryProviderDto();
        dto.setUuid(history.getUuid());
        dto.setName(history.getName());
        dto.setStatus(history.getStatus());
        dto.setMeta(AttributeDefinitionUtils.deserialize(history.getMeta(), MetadataAttribute.class));
        int totalCertificateSize = certificateRepository.findByDiscoveryId(history.getId()).size();
        dto.setTotalCertificatesDiscovered(totalCertificateSize);
        if (history.getStatus() == DiscoveryStatus.IN_PROGRESS) {
            dto.setCertificateData(new ArrayList<>());
            dto.setTotalCertificatesDiscovered(0);
        } else {
            Pageable page = PageRequest.of(request.getPageNumber() <= 0 ? 0 : request.getPageNumber() - 1, request.getItemsPerPage(), Sort.by(Sort.Direction.ASC, "id"));
            dto.setCertificateData(certificateRepository.findAllByDiscoveryId(history.getId(), page).stream().map(Certificate::mapToDto).toList());
        }
        return dto;
    }

    @Override
    public void deleteDiscovery(String uuid) throws NotFoundException {
        DiscoveryHistory discoveryHistory = discoveryHistoryService.getHistoryByUuid(uuid);
        List<Certificate> certificates = certificateRepository.findByDiscoveryId(discoveryHistory.getId());
        certificateRepository.deleteAll(certificates);
        discoveryHistoryService.deleteHistory(discoveryHistory);
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void discoverCertificate(DiscoveryRequestDto request, DiscoveryHistory history) throws NotFoundException {
        try {
            discoverCertificatesInternal(request, history);
        } catch (Exception e) {
            logger.error("Discovery failed for the request with name {}: {}", request.getName(), e.getMessage(), e);
            history.setStatus(DiscoveryStatus.FAILED);
            history.setMeta(AttributeDefinitionUtils.serialize(getReasonMeta(e.getMessage())));
            discoveryHistoryService.setHistory(history);
        }
    }

    private void discoverCertificatesInternal(DiscoveryRequestDto request, DiscoveryHistory history) {
        logger.info("Discovery initiated for the request with name {}", request.getName());
        Set<String> urls = DiscoverIpHandler.getAllIp(request);
        AtomicInteger successUrlCount = new AtomicInteger(0);
        AtomicInteger failedUrlCount = new AtomicInteger(0);
        AtomicInteger foundCertsCount = new AtomicInteger(0);
        Set<String> uniqueCerts = Collections.synchronizedSet(new HashSet<>()); // Thread-safe set

        boolean failed = false;
        List<Future<?>> futures = new ArrayList<>();
        int maxThreads = AttributeServiceImpl.getParallelExecutionsDataAttributeContentValue(request.getAttributes());
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
            for (String url : urls) {
                futures.add(executor.submit(() -> {
                    logger.debug("Discovering certificate for {}", url);
                    try {
                        processCertificatesForUrl(url, history.getId(), uniqueCerts, foundCertsCount);
                        successUrlCount.incrementAndGet();
                    } catch (Exception e) {
                        logger.error("Unable to process data or URL {}: {}", url, e.getMessage());
                        failedUrlCount.incrementAndGet();
                    }
                }));

                if (futures.size() == maxThreads) {
                    status = commitDiscoveredCertsBatch(status, futures, history.getName(), true);
                }
            }
            if (!futures.isEmpty()) {
                commitDiscoveredCertsBatch(status, futures, history.getName(), false);
            }
        } catch (Exception e) {
            failed = true;
            logger.error("An error occurred during discovery: {}", e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        } finally {
            TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());

            logger.info("Discovery {} has total of {} certificates, {} unique, from {} sources", request.getName(), foundCertsCount.get(), uniqueCerts.size(), urls.size());
            history.setStatus(failed ? DiscoveryStatus.FAILED : DiscoveryStatus.COMPLETED);
            history.setMeta(AttributeDefinitionUtils.serialize(getDiscoveryMetadata(urls.size(), successUrlCount.get(), failedUrlCount.get())));
            discoveryHistoryService.setHistory(history);
            logger.info("Discovery Completed. Name of the discovery is {}", request.getName());
            transactionManager.commit(status);
        }
    }

    private TransactionStatus commitDiscoveredCertsBatch(TransactionStatus status, List<Future<?>> futures, String discoveryName, boolean createNewTransaction) throws ExecutionException, InterruptedException {
        logger.debug("Waiting for {} URL discovery tasks for discovery {}", futures.size(), discoveryName);
        for (Future<?> future : futures) {
            future.get();
        }
        logger.debug("{} URL discovery tasks for discovery {} finished", futures.size(), discoveryName);
        futures.clear();
        transactionManager.commit(status);

        return createNewTransaction ? transactionManager.getTransaction(new DefaultTransactionDefinition()) : null;
    }

    private void processCertificatesForUrl(String url, Long historyId, Set<String> uniqueCerts, AtomicInteger foundCertsCount) throws IOException, NoSuchAlgorithmException, KeyManagementException, CertificateEncodingException {
        ConnectionResponse connection = connectionService.getCertificates(url);
        logger.debug("Connection to the url success. Certificates obtained");
        X509Certificate[] certificates = connection.getCertificates();
        for (X509Certificate certificate : certificates) {
            String base64Content = Base64.getEncoder().encodeToString(certificate.getEncoded());
            foundCertsCount.incrementAndGet(); // + to all certificates count
            if (uniqueCerts.add(base64Content)) {
                createCertificateEntry(certificate, historyId, url);
            }
        }
    }

    private void createCertificateEntry(X509Certificate certificate, Long discoveryId, String discoverySource) throws CertificateEncodingException {
        Certificate cert = new Certificate();
        String base64Content = Base64.getEncoder().encodeToString(certificate.getEncoded());
        if (certificateRepository.findByDiscoveryIdAndBase64Content(discoveryId, base64Content).isEmpty()) {
            cert.setDiscoveryId(discoveryId);
            cert.setMeta(AttributeDefinitionUtils.serialize(getCertificateMetadata(discoverySource)));
            cert.setBase64Content(base64Content);
            cert.setUuid(UUID.randomUUID().toString());
            certificateRepository.save(cert);
        }
    }

    private List<MetadataAttribute> getDiscoveryMetadata(Integer totalUrls, Integer successUrls, Integer failedUrls) {
        List<MetadataAttribute> attributes = new ArrayList<>();

        //Total URL
        MetadataAttribute totalAttribute = new MetadataAttribute();
        totalAttribute.setName("totalUrls");
        totalAttribute.setUuid("872ca286-601f-11ed-9b6a-0242ac120002");
        totalAttribute.setContentType(AttributeContentType.INTEGER);
        totalAttribute.setType(AttributeType.META);
        totalAttribute.setDescription("Total number of URLs for the discovery");

        MetadataAttributeProperties totalAttributeProperties = new MetadataAttributeProperties();
        totalAttributeProperties.setLabel("Total URLs");
        totalAttributeProperties.setVisible(true);

        totalAttribute.setProperties(totalAttributeProperties);
        totalAttribute.setContent(List.of(new IntegerAttributeContent(totalUrls.toString(), totalUrls)));
        attributes.add(totalAttribute);

        //Success URL
        MetadataAttribute successAttribute = new MetadataAttribute();
        successAttribute.setName("successUrls");
        successAttribute.setUuid("872ca600-601f-11ed-9b6a-0242ac120002");
        successAttribute.setContentType(AttributeContentType.INTEGER);
        successAttribute.setType(AttributeType.META);
        successAttribute.setDescription("Successful certificate discovery URLs");

        MetadataAttributeProperties successAttributeProperties = new MetadataAttributeProperties();
        successAttributeProperties.setLabel("No Of Success URLs");
        successAttributeProperties.setVisible(true);

        successAttribute.setProperties(successAttributeProperties);
        successAttribute.setContent(List.of(new IntegerAttributeContent(successUrls.toString(), successUrls)));
        attributes.add(successAttribute);

        //Failed URL
        MetadataAttribute failedAttribute = new MetadataAttribute();
        failedAttribute.setName("failedUrls");
        failedAttribute.setUuid("872ca7ea-601f-11ed-9b6a-0242ac120002");
        failedAttribute.setContentType(AttributeContentType.INTEGER);
        failedAttribute.setType(AttributeType.META);
        failedAttribute.setDescription("Failed certificate discovery URLs");

        MetadataAttributeProperties failedAttributeProperties = new MetadataAttributeProperties();
        failedAttributeProperties.setLabel("No Of Failed URLs");
        failedAttributeProperties.setVisible(true);

        failedAttribute.setProperties(failedAttributeProperties);
        failedAttribute.setContent(List.of(new IntegerAttributeContent(failedUrls.toString(), failedUrls)));
        attributes.add(failedAttribute);

        return attributes;
    }

    private List<MetadataAttribute> getCertificateMetadata(String discoverySource) {
        List<MetadataAttribute> attributes = new ArrayList<>();

        //Total URL
        MetadataAttribute attribute = new MetadataAttribute();
        attribute.setName("discoverySource");
        attribute.setUuid("000043aa-6022-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Source from where the certificate is discovered");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Discovery Source");
        attributeProperties.setVisible(true);
        attributeProperties.setGlobal(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContent(discoverySource, discoverySource)));
        attributes.add(attribute);

        return attributes;
    }

    private List<MetadataAttribute> getReasonMeta(String exception) {
        List<MetadataAttribute> attributes = new ArrayList<>();

        //Exception Reason
        MetadataAttribute attribute = new MetadataAttribute();
        attribute.setName("reason");
        attribute.setUuid("abc0412a-60f6-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Reason for failure");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Reason");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContent(exception)));
        attributes.add(attribute);

        return attributes;
    }

}