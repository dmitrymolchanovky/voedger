/*
 * Copyright (c) 2022-present unTill Pro, Ltd.
 */

package blobber

import (
	"github.com/voedger/voedger/pkg/appdef"
	"github.com/voedger/voedger/pkg/iblobstorage"
	"github.com/voedger/voedger/pkg/istructs"
	"github.com/voedger/voedger/pkg/istructsmem"
	"github.com/voedger/voedger/pkg/state"
)

func ProvideBlobberCmds(cfg *istructsmem.AppConfigType) {
	provideUploadBLOBHelperCmd(cfg)
	provideDownloadBLOBHelperCmd(cfg)
}

func provideDownloadBLOBHelperCmd(cfg *istructsmem.AppConfigType) {
	dbhQName := appdef.NewQName(appdef.SysPackage, "DownloadBLOBHelper")

	// this command does nothing. It is called to check Authorization token provided in header only
	downloadBLOBHelperCmd := istructsmem.NewCommandFunction(dbhQName, istructsmem.NullCommandExec)
	cfg.Resources.Add(downloadBLOBHelperCmd)
}

func provideUploadBLOBHelperCmd(cfg *istructsmem.AppConfigType) {
	uploadBLOBHelperCmd := istructsmem.NewCommandFunction(QNameCommandUploadBLOBHelper, ubhExec)
	cfg.Resources.Add(uploadBLOBHelperCmd)
}

func ubhExec(args istructs.ExecCommandArgs) (err error) {
	// write a dummy WDoc<BLOB> to book an ID and then use it as a new BLOB ID
	kb, err := args.State.KeyBuilder(state.Record, QNameWDocBLOB)
	if err != nil {
		return
	}
	vb, err := args.Intents.NewValue(kb)
	if err != nil {
		return
	}
	vb.PutRecordID(appdef.SystemField_ID, 1)
	vb.PutInt32(fldStatus, int32(iblobstorage.BLOBStatus_Unknown))
	return nil
}
