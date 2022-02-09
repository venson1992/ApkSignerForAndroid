package com.android.apksigner;

import java.util.Arrays;

class OptionsParser {
    private int mIndex;
    private String mLastOptionOriginalForm;
    private String mLastOptionValue;
    private final String[] mParams;
    private int mPutBackIndex;
    private String mPutBackLastOptionOriginalForm;
    private String mPutBackLastOptionValue;

    public OptionsParser(String[] params) {
        this.mParams = (String[]) params.clone();
    }

    public String nextOption() {
        if (this.mIndex >= this.mParams.length) {
            return null;
        }
        String param = this.mParams[this.mIndex];
        if (!param.startsWith("-")) {
            return null;
        }
        this.mPutBackIndex = this.mIndex;
        this.mIndex++;
        this.mPutBackLastOptionOriginalForm = this.mLastOptionOriginalForm;
        this.mLastOptionOriginalForm = param;
        this.mPutBackLastOptionValue = this.mLastOptionValue;
        this.mLastOptionValue = null;
        if (!param.startsWith("--")) {
            return param.substring("-".length());
        }
        if ("--".equals(param)) {
            return null;
        }
        int valueDelimiterIndex = param.indexOf(61);
        if (valueDelimiterIndex == -1) {
            return param.substring("--".length());
        }
        this.mLastOptionValue = param.substring(valueDelimiterIndex + 1);
        this.mLastOptionOriginalForm = param.substring(0, valueDelimiterIndex);
        return param.substring("--".length(), valueDelimiterIndex);
    }

    public void putOption() {
        this.mIndex = this.mPutBackIndex;
        this.mLastOptionOriginalForm = this.mPutBackLastOptionOriginalForm;
        this.mLastOptionValue = this.mPutBackLastOptionValue;
    }

    public String getOptionOriginalForm() {
        return this.mLastOptionOriginalForm;
    }

    public String getRequiredValue(String valueDescription) throws OptionsException {
        if (this.mLastOptionValue != null) {
            String result = this.mLastOptionValue;
            this.mLastOptionValue = null;
            return result;
        } else if (this.mIndex >= this.mParams.length) {
            throw new OptionsException(valueDescription + " missing after " + this.mLastOptionOriginalForm);
        } else {
            String param = this.mParams[this.mIndex];
            if ("--".equals(param)) {
                throw new OptionsException(valueDescription + " missing after " + this.mLastOptionOriginalForm);
            }
            this.mIndex++;
            return param;
        }
    }

    public int getRequiredIntValue(String valueDescription) throws OptionsException {
        String value = getRequiredValue(valueDescription);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new OptionsException(valueDescription + " (" + this.mLastOptionOriginalForm + ") must be a decimal number: " + value);
        }
    }

    public boolean getOptionalBooleanValue(boolean defaultValue) throws OptionsException {
        if (this.mLastOptionValue != null) {
            String stringValue = this.mLastOptionValue;
            this.mLastOptionValue = null;
            if ("true".equals(stringValue)) {
                return true;
            }
            if ("false".equals(stringValue)) {
                return false;
            }
            throw new OptionsException("Unsupported value for " + this.mLastOptionOriginalForm + ": " + stringValue + ". Only true or false supported.");
        } else if (this.mIndex >= this.mParams.length) {
            return defaultValue;
        } else {
            String stringValue2 = this.mParams[this.mIndex];
            if ("true".equals(stringValue2)) {
                this.mIndex++;
                return true;
            } else if (!"false".equals(stringValue2)) {
                return defaultValue;
            } else {
                this.mIndex++;
                return false;
            }
        }
    }

    public String[] getRemainingParams() {
        if (this.mIndex >= this.mParams.length) {
            return new String[0];
        }
        if ("--".equals(this.mParams[this.mIndex])) {
            return (String[]) Arrays.copyOfRange(this.mParams, this.mIndex + 1, this.mParams.length);
        }
        return (String[]) Arrays.copyOfRange(this.mParams, this.mIndex, this.mParams.length);
    }

    public static class OptionsException extends Exception {
        private static final long serialVersionUID = 1;

        public OptionsException(String message) {
            super(message);
        }
    }
}
