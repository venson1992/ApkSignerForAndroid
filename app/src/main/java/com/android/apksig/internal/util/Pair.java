package com.android.apksig.internal.util;

public final class Pair<A, B> {
    private final A mFirst;
    private final B mSecond;

    private Pair(A first, B second) {
        this.mFirst = first;
        this.mSecond = second;
    }

    public static <A, B> Pair<A, B> of(A first, B second) {
        return new Pair<>(first, second);
    }

    public A getFirst() {
        return this.mFirst;
    }

    public B getSecond() {
        return this.mSecond;
    }

    public int hashCode() {
        int i = 0;
        int hashCode = ((this.mFirst == null ? 0 : this.mFirst.hashCode()) + 31) * 31;
        if (this.mSecond != null) {
            i = this.mSecond.hashCode();
        }
        return hashCode + i;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        Pair other = (Pair) obj;
        if (this.mFirst == null) {
            if (other.mFirst != null) {
                return false;
            }
        } else if (!this.mFirst.equals(other.mFirst)) {
            return false;
        }
        return this.mSecond == null ? other.mSecond == null : this.mSecond.equals(other.mSecond);
    }
}
