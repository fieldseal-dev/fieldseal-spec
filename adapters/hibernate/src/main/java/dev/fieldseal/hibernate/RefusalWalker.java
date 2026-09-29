package dev.fieldseal.hibernate;

import org.hibernate.metamodel.model.domain.EntityDomainType;
import org.hibernate.query.sqm.ComparisonOperator;
import org.hibernate.query.sqm.spi.BaseSemanticQueryWalker;
import org.hibernate.query.sqm.tree.domain.SqmBasicValuedSimplePath;
import org.hibernate.query.sqm.tree.domain.SqmPath;
import org.hibernate.query.sqm.tree.expression.SqmAggregateFunction;
import org.hibernate.query.sqm.tree.expression.SqmFunction;
import org.hibernate.query.sqm.tree.insert.SqmConflictClause;
import org.hibernate.query.sqm.tree.insert.SqmInsertSelectStatement;
import org.hibernate.query.sqm.tree.insert.SqmInsertValuesStatement;
import org.hibernate.query.sqm.tree.predicate.SqmComparisonPredicate;
import org.hibernate.query.sqm.tree.predicate.SqmInListPredicate;
import org.hibernate.query.sqm.tree.predicate.SqmJunctionPredicate;
import org.hibernate.query.sqm.tree.predicate.SqmNegatedPredicate;
import org.hibernate.query.sqm.tree.predicate.SqmNullnessPredicate;
import org.hibernate.query.sqm.tree.select.SqmDynamicInstantiation;
import org.hibernate.query.sqm.tree.select.SqmQuerySpec;
import org.hibernate.query.sqm.tree.select.SqmSelectClause;
import org.hibernate.query.sqm.tree.select.SqmSelection;
import org.hibernate.query.sqm.tree.select.SqmSortSpecification;
import org.hibernate.query.sqm.tree.update.SqmAssignment;

/**
 * The query-side refusals of docs/29 §3.3, over a statement's semantic tree, before SQL exists.
 *
 * <p><b>Default-deny.</b> An encrypted attribute {@code E} or an index attribute {@code I} is
 * refused wherever it appears, unless its <em>direct</em> parent is one of the few nodes that
 * allow it, and that parent checks the child itself instead of visiting it: a top-level,
 * non-distinct selection; {@code is [not] null}; a plain {@code count(x)}; {@code order by I};
 * and, inside the finder's scope only, {@code I = ?} and {@code I in (…)} outside any negation.
 * Every other route to a path reaches {@link #visitBasicValuedPath} and is refused there, so an
 * expression kind this class does not know about is refused rather than let through, and a path
 * node the tree shares between two positions is judged at each.
 */
final class RefusalWalker extends BaseSemanticQueryWalker {

    private enum Position { SELECT, NULLNESS, COUNT, ORDER, INDEX_MATCH, OTHER }

    private final FieldsealRuntime runtime;
    private final boolean finderScope;
    /** Nesting of query parts: 0 is the statement's own, above 0 a subquery or CTE. */
    private int depth = -1;
    private int negations;
    private boolean distinctSelect;

    RefusalWalker(FieldsealRuntime runtime, boolean finderScope) {
        this.runtime = runtime;
        this.finderScope = finderScope;
    }

    // ---- positions that allow a direct child -----------------------------------------------

    @Override
    public Object visitQuerySpec(SqmQuerySpec<?> querySpec) {
        depth++;
        boolean outer = distinctSelect;
        try {
            return super.visitQuerySpec(querySpec);
        } finally {
            distinctSelect = outer;
            depth--;
        }
    }

    @Override
    public Object visitSelectClause(SqmSelectClause selectClause) {
        distinctSelect = selectClause.isDistinct();
        return super.visitSelectClause(selectClause);
    }

    @Override
    public Object visitSelection(SqmSelection<?> selection) {
        if (!direct(selection.getSelectableNode(), selectPosition())) {
            selection.getSelectableNode().accept(this);
        }
        return selection;
    }

    @Override
    public Object visitDynamicInstantiation(SqmDynamicInstantiation<?> instantiation) {
        for (var argument : instantiation.getArguments()) {
            if (!direct(argument.getSelectableNode(), selectPosition())) {
                argument.getSelectableNode().accept(this);
            }
        }
        return instantiation;
    }

    private Position selectPosition() {
        return depth == 0 && !distinctSelect ? Position.SELECT : Position.OTHER;
    }

    @Override
    public Object visitIsNullPredicate(SqmNullnessPredicate predicate) {
        if (!direct(predicate.getExpression(), Position.NULLNESS)) {
            predicate.getExpression().accept(this);
        }
        return predicate;
    }

    @Override
    public Object visitFunction(SqmFunction<?> function) {
        boolean plainCount = function.getFunctionName().equalsIgnoreCase("count")
                && function.getArguments().size() == 1
                && function.getArguments().get(0) instanceof SqmBasicValuedSimplePath<?>;
        if (plainCount) {
            direct(function.getArguments().get(0), Position.COUNT);
            if (function instanceof SqmAggregateFunction<?> aggregate
                    && aggregate.getFilter() != null) {
                aggregate.getFilter().accept(this);
            }
            return function;
        }
        return super.visitFunction(function);
    }

    @Override
    public Object visitSortSpecification(SqmSortSpecification sort) {
        if (!direct(sort.getSortExpression(), Position.ORDER)) {
            sort.getSortExpression().accept(this);
        }
        return sort;
    }

    @Override
    public Object visitComparisonPredicate(SqmComparisonPredicate predicate) {
        Position p = matchPosition(predicate.isNegated())
                && predicate.getSqmOperator() == ComparisonOperator.EQUAL
                ? Position.INDEX_MATCH : Position.OTHER;
        if (!direct(predicate.getLeftHandExpression(), p)) {
            predicate.getLeftHandExpression().accept(this);
        }
        if (!direct(predicate.getRightHandExpression(), p)) {
            predicate.getRightHandExpression().accept(this);
        }
        return predicate;
    }

    @Override
    public Object visitInListPredicate(SqmInListPredicate<?> predicate) {
        Position p = matchPosition(predicate.isNegated()) ? Position.INDEX_MATCH : Position.OTHER;
        if (!direct(predicate.getTestExpression(), p)) {
            predicate.getTestExpression().accept(this);
        }
        for (var e : predicate.getListExpressions()) {
            e.accept(this);
        }
        return predicate;
    }

    private boolean matchPosition(boolean negated) {
        return finderScope && negations == 0 && !negated;
    }

    @Override
    public Object visitNegatedPredicate(SqmNegatedPredicate predicate) {
        negations++;
        try {
            return super.visitNegatedPredicate(predicate);
        } finally {
            negations--;
        }
    }

    @Override
    public Object visitJunctionPredicate(SqmJunctionPredicate predicate) {
        boolean negated = predicate.isNegated();
        if (negated) {
            negations++;
        }
        try {
            return super.visitJunctionPredicate(predicate);
        } finally {
            if (negated) {
                negations--;
            }
        }
    }

    // ---- write targets -----------------------------------------------------------------------

    @Override
    public Object visitAssignment(SqmAssignment<?> assignment) {
        target(assignment.getTargetPath());
        assignment.getValue().accept(this);
        return assignment;
    }

    @Override
    public Object visitInsertValuesStatement(SqmInsertValuesStatement<?> statement) {
        statement.getInsertionTargetPaths().forEach(this::target);
        return super.visitInsertValuesStatement(statement);
    }

    @Override
    public Object visitInsertSelectStatement(SqmInsertSelectStatement<?> statement) {
        statement.getInsertionTargetPaths().forEach(this::target);
        return super.visitInsertSelectStatement(statement);
    }

    @Override
    public Object visitConflictClause(SqmConflictClause<?> clause) {
        clause.getConstraintPaths().forEach(this::target);
        return super.visitConflictClause(clause);
    }

    private void target(SqmPath<?> path) {
        String[] where = locate(path);
        if (where == null) {
            return;
        }
        ColumnSpec e = runtime.column(where[0], where[1]);
        IndexSpec i = runtime.index(where[0], where[1]);
        String label = e != null ? e.label : i != null ? i.label : null;
        if (label != null) {
            throw new FieldsealNotSupportedException(label + " is the target of an HQL or "
                    + "Criteria update or insert. A bulk mutation runs in the database and "
                    + "bypasses the adapter's listener, which is the only place an envelope and "
                    + "its blind index are written together; even `= null` would leave the "
                    + "index sibling stale (spec §10.2's NULL invariant). Load the entities and "
                    + "change them, or use StatelessSession.update (docs/29 §3.3)");
        }
    }

    // ---- the check -------------------------------------------------------------------------

    /**
     * Judges {@code node} at {@code position} if it is a path to an attribute; returns false if
     * it is not a path at all, for the caller to visit it normally.
     */
    private boolean direct(Object node, Position position) {
        if (!(node instanceof SqmBasicValuedSimplePath<?> path)) {
            return false;
        }
        check(path, position);
        return true;
    }

    @Override
    public Object visitBasicValuedPath(SqmBasicValuedSimplePath<?> path) {
        check(path, Position.OTHER);
        return path;
    }

    private void check(SqmBasicValuedSimplePath<?> path, Position position) {
        String[] where = locate(path);
        if (where == null) {
            return;
        }
        ColumnSpec e = runtime.column(where[0], where[1]);
        if (e != null) {
            switch (position) {
                case SELECT, NULLNESS, COUNT -> {
                    return;
                }
                case ORDER -> throw refuse(e.label, "is ordered by. Ordering compares envelope "
                        + "bytes, a meaningless order that looks stable (spec §10.2, G20)");
                default -> throw refuse(e.label, "is compared, computed on, grouped, selected "
                        + "distinct or selected in a subquery, all of which the database would "
                        + "do on envelope bytes. Every envelope is randomized, so a comparison "
                        + "matches nothing and a computation is meaningless. Only `is [not] "
                        + "null`, a plain count() and a top-level selection are served; to find "
                        + "rows by value, query its @BlindIndex through FieldsealQueries "
                        + "(spec §10.2, §7.10)");
            }
        }
        IndexSpec i = runtime.index(where[0], where[1]);
        if (i != null) {
            switch (position) {
                case SELECT, NULLNESS, COUNT, ORDER, INDEX_MATCH -> {
                    return;
                }
                default -> {
                    if (negations > 0) {
                        throw refuse(i.label, "is under a negation. A blind index match set is "
                                + "a bucket, and excluding a bucket drops rows whose value "
                                + "differs; they never reach the application, so spec §7.5 "
                                + "cannot put them back (spec §10.2, G24)");
                    }
                    throw refuse(i.label, "is queried outside FieldsealQueries. A blind index "
                            + "returns candidates, which include values that collide under "
                            + "spec §7.4's truncation, and only the finder re-verifies them "
                            + "(spec §7.5). Use FieldsealQueries.of(session, Entity.class)"
                            + ".whereIndex(\"" + i.attribute + "\", value)");
                }
            }
        }
    }

    /** {@code {entityName, attribute}} for a path to an entity's basic attribute, or null. */
    private static String[] locate(SqmPath<?> path) {
        SqmPath<?> lhs = path.getLhs();
        if (lhs == null) {
            return null;
        }
        if (lhs.getReferencedPathSource().getPathType() instanceof EntityDomainType<?> owner) {
            return new String[] {owner.getHibernateEntityName(),
                    path.getReferencedPathSource().getPathName()};
        }
        return null;
    }

    private static FieldsealNotSupportedException refuse(String label, String why) {
        return new FieldsealNotSupportedException(label + " " + why + " (docs/29 §3.3)");
    }
}
