/*
 * Copyright © 2023 AmneziaVPN. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg;

import org.amnezia.awg.config.Config;
import org.amnezia.awg.config.Peer;
import org.amnezia.awg.config.XrayProtocol;

import java.util.Locale;

public class Xray {
    public static String generate(final Config config) {
        if (config.getInterface().getXrayProtocol() != XrayProtocol.TCP) {
            return "";
        }

        final Peer peer = config.getPeers().get(0);
        final String host = peer.getEndpoint().get().getHost();
        final int port = peer.getEndpoint().get().getPort();

        return String.format(Locale.ROOT, "{\n" +
                "  \"inbounds\": [\n" +
                "    {\n" +
                "      \"port\": 1080,\n" +
                "      \"listen\": \"127.0.0.1\",\n" +
                "      \"protocol\": \"socks\",\n" +
                "      \"settings\": {\n" +
                "        \"auth\": \"noauth\",\n" +
                "        \"udp\": true\n" +
                "      }\n" +
                "    }\n" +
                "  ],\n" +
                "  \"outbounds\": [\n" +
                "    {\n" +
                "      \"protocol\": \"freedom\",\n" +
                "      \"settings\": {\n" +
                "        \"vnext\": [\n" +
                "          {\n" +
                "            \"address\": \"%s\",\n" +
                "            \"port\": %d,\n" +
                "            \"users\": []\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}", host, port);
    }
}
