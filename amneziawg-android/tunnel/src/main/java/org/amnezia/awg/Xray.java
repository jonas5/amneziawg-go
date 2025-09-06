/*
 * Copyright © 2023 AmneziaVPN. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg;

import org.amnezia.awg.config.Config;
import org.amnezia.awg.config.XrayProtocol;

public class Xray {
    public static String generate(final Config config) {
        if (config.getInterface().getXrayProtocol() != XrayProtocol.TCP) {
            return "";
        }

        return "{\n" +
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
                "      \"settings\": {}\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }
}
