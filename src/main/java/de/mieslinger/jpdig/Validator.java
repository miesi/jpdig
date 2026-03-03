package de.mieslinger.jpdig;

import java.util.List;
import java.util.Set;

/**
 * Validation logic for NS record consistency, TTLs, and glue records.
 */
public final class Validator {

    private Validator() {}

    private static final long TTL_WARN_THRESHOLD = 3600;
    private static final long TTL_ERROR_THRESHOLD = 600;

    /**
     * Compare delegation NS set with authoritative NS set.
     */
    public static void compareNsSets(Set<String> delegation, Set<String> authoritative,
                                     String zone, List<TraceModel.ValidationMessage> messages) {
        if (delegation.isEmpty() || authoritative.isEmpty()) {
            return;
        }

        if (delegation.equals(authoritative)) {
            messages.add(new TraceModel.ValidationMessage(
                    TraceModel.Severity.OK,
                    "NS sets match for " + zone));
            return;
        }

        // Find differences
        Set<String> onlyInDelegation = new java.util.LinkedHashSet<>(delegation);
        onlyInDelegation.removeAll(authoritative);

        Set<String> onlyInAuthoritative = new java.util.LinkedHashSet<>(authoritative);
        onlyInAuthoritative.removeAll(delegation);

        StringBuilder sb = new StringBuilder();
        sb.append("NS set mismatch for ").append(zone);
        if (!onlyInDelegation.isEmpty()) {
            sb.append(" | only in delegation: ").append(String.join(", ", onlyInDelegation));
        }
        if (!onlyInAuthoritative.isEmpty()) {
            sb.append(" | only in authoritative: ").append(String.join(", ", onlyInAuthoritative));
        }

        messages.add(new TraceModel.ValidationMessage(TraceModel.Severity.WARN, sb.toString()));
    }

    /**
     * Compare delegation TTL with authoritative TTL.
     */
    public static void compareTtls(long delegationTtl, long authoritativeTtl,
                                   String zone, List<TraceModel.ValidationMessage> messages) {
        if (delegationTtl == 0 || authoritativeTtl == 0) return;

        if (delegationTtl == authoritativeTtl) {
            messages.add(new TraceModel.ValidationMessage(
                    TraceModel.Severity.OK,
                    "NS TTLs match for " + zone + " (delegation=" + delegationTtl
                            + " authoritative=" + authoritativeTtl + ")"));
        } else {
            messages.add(new TraceModel.ValidationMessage(
                    TraceModel.Severity.WARN,
                    "NS TTL mismatch for " + zone + " (delegation=" + delegationTtl
                            + " authoritative=" + authoritativeTtl + ")"));
        }
    }

    /**
     * Validate a TTL value against thresholds.
     */
    public static void validateTtl(String context, long ttl,
                                   List<TraceModel.ValidationMessage> messages) {
        if (ttl == 0) return;

        if (ttl < TTL_ERROR_THRESHOLD) {
            messages.add(new TraceModel.ValidationMessage(
                    TraceModel.Severity.ERROR,
                    context + " TTL=" + ttl + "s is critically low (< " + TTL_ERROR_THRESHOLD + "s)"));
        } else if (ttl < TTL_WARN_THRESHOLD) {
            messages.add(new TraceModel.ValidationMessage(
                    TraceModel.Severity.WARN,
                    context + " TTL=" + ttl + "s is low (< " + TTL_WARN_THRESHOLD + "s)"));
        }
    }
}
