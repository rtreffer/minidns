package org.minidns.constants;

import org.minidns.constants.svcbservicekeys.ALPNServiceKey;
import org.minidns.constants.svcbservicekeys.ServiceKeySpecification;
import org.minidns.constants.svcbservicekeys.UnrecognizedServiceKey;


public class SVCBConstants {
    public static ServiceKeySpecification<?> findServiceKeyByNumber(int number, byte[] blob) {
        switch (number) {
            case 1: return new ALPNServiceKey(blob);
            default: return new UnrecognizedServiceKey(blob, number);
        }
    }

    // ALPN(1, "alpn"),
    // NO_DEFAULT_ALPN(2, "no-default-alpn"),
    // PORT(3, "port"),
    // IPV4HINT(4, "ipv4hint"),
    // ECHOCONFIG(5, "echoconfig"),
    // IPV6HINT(6, "ipv6hint"),
    // INVALID_KEY(65535, "key65535");
}
