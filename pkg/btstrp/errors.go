/*
 * Copyright (c) 2024-present unTill Software Development Group B.V.
 * @author Denis Gribanov
 */

package btstrp

import "errors"

var (
	ErrNumPartitionsChanged    = errors.New("num partitions changed")
	ErrNumAppWorkspacesChanged = errors.New("num application workspaces changed")
)