package org.minidns.record;

import org.minidns.constants.SVCBConstants;
import org.minidns.constants.svcbservicekeys.ServiceKeySpecification;
import org.minidns.dnsname.DnsName;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * SVCB Record Type (Service binding)
 *
 * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01">draft-ietf-dnsop-svcb-https-01: Service binding and parameter specification via the DNS (DNS SVCB and HTTPS RRs)</a>
 */
class SVCB extends RRWithTarget {

    /**
     * The priority indicates the SvcPriority.
     * A SvcPriority of 0 puts this RR in AliasMode (otherwise ServiceMode).
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#page-12>SvcPriority</a>
     */
    public final int priority;

    /**
     * A set of key=value pairs (SvcFieldValue).
     * The key is an ID for the parameter.
     *
     * This is a sorted map to follow specification.
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-12.3.2">Possible parameter IDs</a>
     */
    public final Set<ServiceKeySpecification<?>> params;

    /**
     * @param priority SvcPriority
     * @param target TargetName
     * @param params SvcParams
     */
    public SVCB(int priority, DnsName target, Set<ServiceKeySpecification<?>> params) {
        super(target);
        this.priority = priority;
        TreeSet<ServiceKeySpecification<?>> sorted = new TreeSet<>(params);
        this.params = Collections.unmodifiableSortedSet(sorted);
    }

    /**
     * Parses the wireformat data according to the spec.
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-2.2">RDATA wire format specification</a>
     */
    public static SVCB parse(DataInputStream dis, int length, byte[] data)
            throws IOException {
        int priority = dis.readUnsignedShort();
        DnsName target = DnsName.parse(dis, data);
        Set<ServiceKeySpecification<?>> params;

        int paramBlobSize = length - 2 - target.getRawBytes().length;
        if(paramBlobSize == 0) {
            params = Collections.emptySet();
        } else {
            params = parseParamsBlob(dis, length);
        }

        return new SVCB(priority, target, params);
    }

    private static Set<ServiceKeySpecification<?>> parseParamsBlob(DataInputStream dis, int paramBlobSize) throws IOException {
        int remainingBytes = paramBlobSize;
        int lastKey = Integer.MIN_VALUE;
        Set<ServiceKeySpecification<?>> params = new HashSet<>();

        while(remainingBytes > 0) {
            int key = dis.readUnsignedShort();
            if(key < lastKey) throw new IllegalArgumentException("SVCB ServiceKeys must be in ascending order (" + key + "<" + lastKey + ")");
            else if(key == lastKey) throw new IllegalArgumentException("SVCB ServiceKeys must not be duplicate (" + key + "=" + lastKey + ")");
            lastKey = key;

            int valueLength = dis.readUnsignedShort();
            byte[] valueBlob = new byte[valueLength];
            if(valueLength != 0) {
                dis.readFully(valueBlob);
            }

            ServiceKeySpecification<?> detectedKey = SVCBConstants.findServiceKeyByNumber(key, valueBlob);
            params.add(detectedKey);
            remainingBytes = remainingBytes - 4 - valueLength;
        }
        return params;
    }

    @Override
    public void serialize(DataOutputStream dos) throws IOException {
        dos.writeShort(priority);
        super.serialize(dos);
        for (ServiceKeySpecification<?> param: params) {
            dos.writeShort(param.blob.length);
            dos.write(param.blob);
        }
    }

    @Override
    public Record.TYPE getType() {
        return Record.TYPE.SVCB;
    }

    @Override
    public String toString() {
        try {
            return priority + " " + target + createValuesString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String createValuesString() throws IOException {
        StringBuilder builder = new StringBuilder();
        for (ServiceKeySpecification<?> param : params) {
            builder.append(" ");
            builder.append(param.getTextualRepresentation());
            builder.append("=");
            builder.append("\"");
            builder.append(param.valueAsString());
            builder.append("\"");
        }
        return builder.toString();
    }
}
