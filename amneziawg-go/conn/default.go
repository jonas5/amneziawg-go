//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "github.com/amnezia-vpn/amneziawg-go/logger"

func NewDefaultBind() Bind { return NewStdNetBind(nil, logger.NewLogger(logger.LogLevelError, "")) }
