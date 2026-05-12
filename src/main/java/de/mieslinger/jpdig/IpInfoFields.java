package de.mieslinger.jpdig;

import java.util.EnumSet;
import java.util.Set;

/**
 * Selection of IpInfo fields to display, parsed from mtr-style -y/--ipinfo
 * values like "0", "013", or "0,1,3".
 *
 * Digit mapping (mtr-compatible):
 *   0 -> AS number
 *   1 -> IP prefix
 *   2 -> Country code
 *   3 -> RIR
 *   4 -> Allocation date
 *
 * Display order is canonical (AS, PREFIX, COUNTRY, RIR, DATE), independent
 * of input order.
 */
public final class IpInfoFields {

    public enum Field {
        AS, PREFIX, COUNTRY, RIR, DATE
    }

    private final EnumSet<Field> fields;

    private IpInfoFields(EnumSet<Field> fields) {
        this.fields = fields;
    }

    public boolean isEmpty() {
        return fields.isEmpty();
    }

    public boolean contains(Field f) {
        return fields.contains(f);
    }

    public Set<Field> asSet() {
        return fields;
    }

    public static IpInfoFields empty() {
        return new IpInfoFields(EnumSet.noneOf(Field.class));
    }

    /**
     * Parse an mtr-style value. Accepts a comma-separated list of digit
     * groups (e.g. "0,1,3") and/or digit strings (e.g. "013"). Each digit
     * must be 0..4. Empty input or null returns an empty selection.
     */
    public static IpInfoFields parse(String value, boolean addAs) {
        EnumSet<Field> set = EnumSet.noneOf(Field.class);
        if (value != null && !value.isEmpty()) {
            String[] parts = value.split(",");
            for (String part : parts) {
                String p = part.trim();
                if (p.isEmpty()) continue;
                for (int i = 0; i < p.length(); i++) {
                    char c = p.charAt(i);
                    Field f = fromDigit(c);
                    if (f == null) {
                        throw new IllegalArgumentException(
                                "Invalid --ipinfo digit '" + c
                                        + "' (allowed: 0..4) in: " + value);
                    }
                    set.add(f);
                }
            }
        }
        if (addAs) set.add(Field.AS);
        return new IpInfoFields(set);
    }

    private static Field fromDigit(char c) {
        return switch (c) {
            case '0' -> Field.AS;
            case '1' -> Field.PREFIX;
            case '2' -> Field.COUNTRY;
            case '3' -> Field.RIR;
            case '4' -> Field.DATE;
            default -> null;
        };
    }

    public static String label(Field f) {
        return switch (f) {
            case AS -> "AS";
            case PREFIX -> "PREFIX";
            case COUNTRY -> "COUNTRY";
            case RIR -> "RIR";
            case DATE -> "DATE";
        };
    }

    public static String value(Field f, TraceModel.IpInfo info) {
        if (info == null) return null;
        return switch (f) {
            case AS -> info.asn();
            case PREFIX -> info.prefix();
            case COUNTRY -> info.country();
            case RIR -> info.rir();
            case DATE -> info.date();
        };
    }
}
