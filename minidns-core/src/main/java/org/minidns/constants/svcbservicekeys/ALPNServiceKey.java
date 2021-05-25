package org.minidns.constants.svcbservicekeys;

import org.minidns.util.RRTextUtil;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ALPNServiceKey extends ServiceKeySpecification<List<String>> {
    private List<String> value;

    public ALPNServiceKey(byte[] blob) {
        super(blob, 1);
    }

    @Override
    public List<String> value() throws IOException {
        if(value == null) {
            List<String> values = new ArrayList<>();
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(blob));
            while(dis.available() > 0) {
                byte[] blob = new byte[dis.readUnsignedShort()];
                dis.readFully(blob);
                values.add(RRTextUtil.getTextFrom(blob));
            }
            value = Collections.unmodifiableList(values);
        }
        return value;
    }

    @Override
    public String getTextualRepresentation() {
        return "alpn";
    }

    @Override
    public String valueAsString() throws IOException {
        StringBuilder sb = new StringBuilder();
        for (String s : value()) {
            if(sb.length() > 0) {
                sb.append(",");
            }
            sb.append(s.replaceAll(",", "\\\\,"));
        }
        return sb.toString();
    }
}
