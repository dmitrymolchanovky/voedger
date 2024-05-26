/*
 * Copyright (c) 2024-present unTill Software Development Group B.V.
 * @author Denis Gribanov
 */

package cluster

import (
	"github.com/voedger/voedger/pkg/appdef"
	"github.com/voedger/voedger/pkg/appparts"
	"github.com/voedger/voedger/pkg/istructs"
	coreutils "github.com/voedger/voedger/pkg/utils"
)

type update struct {
	coreutils.DML
	setFields     map[string]interface{}
	key           map[string]interface{}
	wsid          istructs.WSID
	id            istructs.RecordID
	partitionID   istructs.PartitionID
	offset        istructs.Offset
	appStructs    istructs.IAppStructs
	appParts      appparts.IAppPartitions
	qNameTypeKind appdef.TypeKind
}
