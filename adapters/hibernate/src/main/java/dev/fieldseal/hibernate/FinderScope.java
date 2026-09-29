package dev.fieldseal.hibernate;

/**
 * Marks the thread while {@link FieldsealQueries} runs its own query, so that {@link
 * RefusalWalker} lets that query's index predicate through (docs/29 §3.1). Translation happens on
 * the calling thread, inside the query's execution, and the finder turns off plan caching for its
 * query, so no cached translation carries the mark to a query outside the scope.
 */
final class FinderScope implements AutoCloseable {
    private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    private FinderScope() {
        DEPTH.set(DEPTH.get() + 1);
    }

    static FinderScope enter() {
        return new FinderScope();
    }

    static boolean active() {
        return DEPTH.get() > 0;
    }

    @Override
    public void close() {
        int d = DEPTH.get() - 1;
        if (d == 0) {
            DEPTH.remove();
        } else {
            DEPTH.set(d);
        }
    }
}
