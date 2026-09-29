package dev.fieldseal.hibernate;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The permission {@link FieldsealQueries} gives its own query, and no other (docs/29 §3.1).
 *
 * <p>The permission is the <em>statement's</em>, not the thread's. Each finder call opens a
 * scope with a token of its own and sets that token as its query's comment, which the translator
 * receives in {@code QueryOptions}; {@link RefusalWalker} lets an index predicate through only
 * for a statement whose comment is a token open on the translating thread. A thread-wide flag was
 * the first design, and was wrong (the #238 review): {@code getResultList()} materializes
 * entities, so application code ({@code @PostLoad}, an interceptor, an event listener) runs on
 * the same thread inside the window, and any query it issued was translated with the permission.
 * Such a query carries no token, so it is refused like any other.
 *
 * <p>The finder also turns off plan caching for its query, so a translation carrying the
 * permission is never reused. The token is a counter, not a secret: this guards against code that
 * runs by accident inside the window, not against code that forges a comment on purpose, which
 * would be the application bypassing its own adapter.
 */
final class FinderScope implements AutoCloseable {
    private static final ThreadLocal<Deque<String>> OPEN = ThreadLocal.withInitial(ArrayDeque::new);
    private static final AtomicLong NEXT = new AtomicLong();

    private final String token;

    private FinderScope() {
        this.token = "fieldseal-finder-" + NEXT.incrementAndGet();
        OPEN.get().push(token);
    }

    static FinderScope enter() {
        return new FinderScope();
    }

    /** The comment the finder puts on its query. */
    String token() {
        return token;
    }

    /** Whether a statement with this comment is a finder's own, open on this thread. */
    static boolean permits(String comment) {
        return comment != null && OPEN.get().contains(comment);
    }

    @Override
    public void close() {
        Deque<String> open = OPEN.get();
        open.remove(token);
        if (open.isEmpty()) {
            OPEN.remove();
        }
    }
}
