package org.minidns.constants.svcbservicekeys;

import java.io.IOException;

public abstract class ServiceKeySpecification<ValueType> implements Comparable<ServiceKeySpecification<?>> {
    public final byte[] blob;
    public final int number;

    public ServiceKeySpecification(byte[] blob, int number) {
        this.blob = blob;
        this.number = number;
    }

    public final int getNumber() {
        return number;
    }

    abstract public ValueType value() throws IOException;
    abstract public String getTextualRepresentation();
    abstract public String valueAsString() throws IOException;

    @Override
    public int compareTo(ServiceKeySpecification<?> other) {
        return getNumber() - other.getNumber();
    }

    @Override
    public String toString() {
        return getTextualRepresentation();
    }
}