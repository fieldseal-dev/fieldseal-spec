package dev.fieldseal.core.keyprovider;

/**
 * The key-provider SPI (spec §8; docs/09 §8.1), which callers implement. Its methods arrive at
 * S4, with the Static, Derived and Envelope providers (docs/27 §8).
 */
public interface KeyProvider {}
