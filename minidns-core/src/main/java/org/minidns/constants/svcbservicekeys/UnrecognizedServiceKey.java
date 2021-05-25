package org.minidns.constants.svcbservicekeys;

import java.util.Arrays;

public class UnrecognizedServiceKey extends ServiceKeySpecification<byte[]>{
    public UnrecognizedServiceKey(byte[] blob, int number) {
        super(blob, number);
    }

    @Override
    public byte[] value() {
        return blob;
    }

    @Override
    public String getTextualRepresentation() {
        return "key" + number;
    }

    @Override
    public String valueAsString() {
        return Arrays.toString(blob);
    }
}
