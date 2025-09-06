/*
 * Copyright © 2023 AmneziaVPN. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.config;

import java.util.Locale;

public enum XrayProtocol {
    UDP,
    TCP,
    AUTO;

    public static XrayProtocol newInstance(String text) {
        for (XrayProtocol protocol : XrayProtocol.values()) {
            if (protocol.name().toLowerCase(Locale.ROOT).equals(text)) {
                return protocol;
            }
        }
        return AUTO;
    }
}
