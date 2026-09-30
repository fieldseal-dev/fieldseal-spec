package dev.fieldseal.hibernate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.hibernate.boot.spi.SessionFactoryOptions;
import org.hibernate.cache.cfg.spi.DomainDataRegionBuildingContext;
import org.hibernate.cache.cfg.spi.DomainDataRegionConfig;
import org.hibernate.cache.spi.support.DomainDataStorageAccess;
import org.hibernate.cache.spi.support.RegionFactoryTemplate;
import org.hibernate.cache.spi.support.StorageAccess;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.engine.spi.SharedSessionContractImplementor;

/**
 * A map-backed cache that records every value put into it, so that a test can see what a cache
 * region would hold. Hibernate core ships no in-memory region factory, and a query cache needs
 * one before it can be switched on at all.
 */
public final class RecordingRegionFactory extends RegionFactoryTemplate {
    private static final long serialVersionUID = 1L;

    /** Every value put into any region, as {@code String.valueOf}, in order. */
    static final List<String> PUTS = Collections.synchronizedList(new ArrayList<>());

    private static final class MapAccess implements DomainDataStorageAccess {
        private final Map<Object, Object> map = new ConcurrentHashMap<>();

        @Override
        public Object getFromCache(Object key, SharedSessionContractImplementor session) {
            return map.get(key);
        }

        @Override
        public void putIntoCache(Object key, Object value,
                SharedSessionContractImplementor session) {
            PUTS.add(String.valueOf(value));
            map.put(key, value);
        }

        @Override
        public boolean contains(Object key) {
            return map.containsKey(key);
        }

        @Override
        public void evictData() {
            map.clear();
        }

        @Override
        public void evictData(Object key) {
            map.remove(key);
        }

        @Override
        public void release() {
            map.clear();
        }
    }

    @Override
    protected DomainDataStorageAccess createDomainDataStorageAccess(
            DomainDataRegionConfig regionConfig, DomainDataRegionBuildingContext context) {
        return new MapAccess();
    }

    @Override
    protected StorageAccess createQueryResultsRegionStorageAccess(String regionName,
            SessionFactoryImplementor sessionFactory) {
        return new MapAccess();
    }

    @Override
    protected StorageAccess createTimestampsRegionStorageAccess(String regionName,
            SessionFactoryImplementor sessionFactory) {
        return new MapAccess();
    }

    @Override
    protected void prepareForUse(SessionFactoryOptions settings, Map<String, Object> config) {}

    @Override
    protected void releaseFromUse() {}
}
