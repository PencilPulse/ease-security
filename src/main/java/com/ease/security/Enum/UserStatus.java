package com.ease.security.Enum;

public enum UserStatus {

    ACTIVE(1),
    INACTIVE(2),
    BLOCKED(3),
    DELETED(4);

    private final int value;

    UserStatus(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static UserStatus fromValue(int value) {
        for (UserStatus status : UserStatus.values()) {
            if (status.value == value) {
                return status;
            }
        }
        throw new IllegalArgumentException("Invalid UserStatus value: " + value);
    }

}
