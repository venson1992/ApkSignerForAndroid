package com.android.apksig.internal.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class InclusiveIntRange {
    private final int max;
    private final int min;

    private InclusiveIntRange(int min2, int max2) {
        this.min = min2;
        this.max = max2;
    }

    public int getMin() {
        return this.min;
    }

    public int getMax() {
        return this.max;
    }

    public static InclusiveIntRange fromTo(int min2, int max2) {
        return new InclusiveIntRange(min2, max2);
    }

    public static InclusiveIntRange from(int min2) {
        return new InclusiveIntRange(min2, Integer.MAX_VALUE);
    }

    public List<InclusiveIntRange> getValuesNotIn(List<InclusiveIntRange> sortedNonOverlappingRanges) {
        if (sortedNonOverlappingRanges.isEmpty()) {
            return Collections.singletonList(this);
        }
        int testValue = this.min;
        List<InclusiveIntRange> result = null;
        for (InclusiveIntRange range : sortedNonOverlappingRanges) {
            int rangeMax = range.max;
            if (testValue <= rangeMax) {
                int rangeMin = range.min;
                if (testValue < range.min) {
                    if (result == null) {
                        result = new ArrayList<>();
                    }
                    result.add(fromTo(testValue, rangeMin - 1));
                }
                if (rangeMax < this.max) {
                    testValue = rangeMax + 1;
                } else if (result == null) {
                    return Collections.emptyList();
                } else {
                    return result;
                }
            }
        }
        if (testValue <= this.max) {
            if (result == null) {
                result = new ArrayList<>(1);
            }
            result.add(fromTo(testValue, this.max));
        }
        return result == null ? Collections.emptyList() : result;
    }

    public String toString() {
        return "[" + this.min + ", " + (this.max < Integer.MAX_VALUE ? this.max + "]" : "∞)");
    }
}
