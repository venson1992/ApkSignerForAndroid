//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.android.apksigner;

import java.util.Arrays;

class OptionsParser {
    private final String[] mParams;
    private int mIndex;
    private int mPutBackIndex;
    private String mLastOptionValue;
    private String mPutBackLastOptionValue;
    private String mLastOptionOriginalForm;
    private String mPutBackLastOptionOriginalForm;

    public OptionsParser(String[] params) {
        this.mParams = (String[]) params.clone();
    }

    public String nextOption() {
        if (this.mIndex >= this.mParams.length) {
            return null;
        } else {
            String param = this.mParams[this.mIndex];
            if (!param.startsWith("-")) {
                return null;
            } else {
                this.mPutBackIndex = this.mIndex++;
                this.mPutBackLastOptionOriginalForm = this.mLastOptionOriginalForm;
                this.mLastOptionOriginalForm = param;
                this.mPutBackLastOptionValue = this.mLastOptionValue;
                this.mLastOptionValue = null;
                if (param.startsWith("--")) {
                    if ("--".equals(param)) {
                        return null;
                    } else {
                        int valueDelimiterIndex = param.indexOf(61);
                        if (valueDelimiterIndex != -1) {
                            this.mLastOptionValue = param.substring(valueDelimiterIndex + 1);
                            this.mLastOptionOriginalForm = param.substring(0, valueDelimiterIndex);
                            return param.substring("--".length(), valueDelimiterIndex);
                        } else {
                            return param.substring("--".length());
                        }
                    }
                } else {
                    return param.substring("-".length());
                }
            }
        }
    }

    public void putOption() {
        this.mIndex = this.mPutBackIndex;
        this.mLastOptionOriginalForm = this.mPutBackLastOptionOriginalForm;
        this.mLastOptionValue = this.mPutBackLastOptionValue;
    }

    public String getOptionOriginalForm() {
        return this.mLastOptionOriginalForm;
    }

    public String getRequiredValue(String valueDescription) throws OptionsParser.OptionsException {
        String param;
        if (this.mLastOptionValue != null) {
            param = this.mLastOptionValue;
            this.mLastOptionValue = null;
            return param;
        } else if (this.mIndex >= this.mParams.length) {
            throw new OptionsParser.OptionsException(valueDescription + " missing after " + this.mLastOptionOriginalForm);
        } else {
            param = this.mParams[this.mIndex];
            if ("--".equals(param)) {
                throw new OptionsParser.OptionsException(valueDescription + " missing after " + this.mLastOptionOriginalForm);
            } else {
                ++this.mIndex;
                return param;
            }
        }
    }

    public int getRequiredIntValue(String valueDescription) throws OptionsParser.OptionsException {
        String value = this.getRequiredValue(valueDescription);

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException var4) {
            throw new OptionsParser.OptionsException(valueDescription + " (" + this.mLastOptionOriginalForm + ") must be a decimal number: " + value);
        }
    }

    public boolean getOptionalBooleanValue(boolean defaultValue) throws OptionsParser.OptionsException {
        String stringValue;
        if (this.mLastOptionValue != null) {
            stringValue = this.mLastOptionValue;
            this.mLastOptionValue = null;
            if ("true".equals(stringValue)) {
                return true;
            } else if ("false".equals(stringValue)) {
                return false;
            } else {
                throw new OptionsParser.OptionsException("Unsupported value for " + this.mLastOptionOriginalForm + ": " + stringValue + ". Only true or false supported.");
            }
        } else if (this.mIndex >= this.mParams.length) {
            return defaultValue;
        } else {
            stringValue = this.mParams[this.mIndex];
            if ("true".equals(stringValue)) {
                ++this.mIndex;
                return true;
            } else if ("false".equals(stringValue)) {
                ++this.mIndex;
                return false;
            } else {
                return defaultValue;
            }
        }
    }

    public String[] getRemainingParams() {
        if (this.mIndex >= this.mParams.length) {
            return new String[0];
        } else {
            String param = this.mParams[this.mIndex];
            return "--".equals(param) ? (String[]) Arrays.copyOfRange(this.mParams, this.mIndex + 1, this.mParams.length) : (String[]) Arrays.copyOfRange(this.mParams, this.mIndex, this.mParams.length);
        }
    }

    public static class OptionsException extends Exception {
        private static final long serialVersionUID = 1L;

        public OptionsException(String message) {
            super(message);
        }
    }
}
