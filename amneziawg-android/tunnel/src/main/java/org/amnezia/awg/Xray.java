package org.amnezia.awg;

import org.amnezia.awg.config.Config;
import org.amnezia.awg.config.InetEndpoint;
import org.amnezia.awg.config.Peer;
import org.amnezia.awg.config.XrayProtocol;

public class Xray {
    public static String generate(final Config config) {
        if (config.getInterface().getXrayProtocol() == XrayProtocol.UDP) {
            return "";
        }
        final Peer peer = config.getPeers().get(0);
        final InetEndpoint endpoint = peer.getEndpoint().orElse(null);
        if (endpoint == null) {
            return "";
        }
        final String endpointAddr = endpoint.getResolved().get().getHostAddress();
        final int endpointPort = endpoint.getPort();

        return "{\n" +
                "  \"inbounds\": [\n" +
                "    {\n" +
                "      \"listen\": \"127.0.0.1\",\n" +
                "      \"port\": " + 27182 + ",\n" +
                "      \"protocol\": \"dokodemo-door\",\n" +
                "      \"settings\": {\n" +
                "        \"network\": \"tcp\",\n" +
                "        \"address\": \"" + endpointAddr + "\",\n" +
                "        \"port\": " + endpointPort + "\n" +
                "      },\n" +
                "      \"tag\": \"inbound\"\n" +
                "    }\n" +
                "  ],\n" +
                "  \"outbounds\": [\n" +
                "    {\n" +
                "      \"protocol\": \"freedom\",\n" +
                "      \"tag\": \"outbound\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }
}
