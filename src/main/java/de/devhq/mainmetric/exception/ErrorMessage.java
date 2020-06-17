package de.devhq.mainmetric.exception;

import java.text.MessageFormat;

import com.fasterxml.jackson.annotation.JsonFormat;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)


public enum ErrorMessage {
    USERID_MUST_BE_VALID("ms-mainmetric-001", "User id must be positive number existing in solution server!"),
    DATA_NOT_FOUND_IN_DB("ms-mainmetric-002", "Requested data not found in database!"),
    NO_SUCH_ELEMENT_FOUND_IN_INTEGRATED_SERVICE("ms-mainmetric-003", "Metric id {0} is invalid! We coudn't find it in our dictionary database. Note that metric names are case-sensitive!");

    private String code;
    private String message;

    private ErrorMessage(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void customizeMessage(String arg) {
        this.message = MessageFormat.format(this.message, arg);
    }

}
