/*
 * Copyright (c) 2021-present Sigma-Soft, Ltd.
 * @author: Nikolay Nikitin
 */

package appdef

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicUsage(t *testing.T) {
	appDef := New()

	saleParamsDef := appDef.AddODoc(NewQName("test", "Sale"))
	saleParamsDef.
		AddStringField("Buyer", true, MaxLen(100)).
		AddField("Age", DataKind_int32, false).
		AddField("Height", DataKind_float32, false).
		AddField("isHuman", DataKind_bool, false).
		AddField("Photo", DataKind_bytes, false)
	saleParamsDef.
		AddContainer("Basket", NewQName("test", "Basket"), 1, 1)

	basketDef := appDef.AddORecord(NewQName("test", "Basket"))
	basketDef.AddContainer("Good", NewQName("test", "Good"), 0, Occurs_Unbounded)

	goodDef := appDef.AddORecord(NewQName("test", "Good"))
	goodDef.
		AddField("Name", DataKind_string, true).
		AddField("Code", DataKind_int64, true).
		AddField("Weight", DataKind_float64, false)

	saleSecureParamsDef := appDef.AddObject(NewQName("test", "saleSecureArgs"))
	saleSecureParamsDef.
		AddField("password", DataKind_string, true)

	docName := NewQName("test", "photos")
	docDef := appDef.AddCDoc(docName)
	docDef.
		AddStringField("Buyer", true, MaxLen(100)).
		AddField("Age", DataKind_int32, false).
		AddField("Height", DataKind_float32, false).
		AddField("isHuman", DataKind_bool, false).
		AddField("Photo", DataKind_bytes, false)

	viewDef := appDef.AddView(NewQName("test", "viewBuyerByHeight"))
	viewDef.Key().Partition().AddField("Height", DataKind_float32)
	viewDef.Key().ClustCols().AddStringField("Buyer", 100)
	viewDef.Value().AddRefField("BuyerID", true, docName)

	objBuyer := appDef.AddObject(NewQName("test", "buyer"))
	objBuyer.
		AddStringField("Name", true).
		AddField("Age", DataKind_int32, false).
		AddField("isHuman", DataKind_bool, false)

	newBuyerCmd := appDef.AddCommand(NewQName("test", "cmdNewBuyer"))
	newBuyerCmd.SetArg(objBuyer.QName())
	newBuyerCmd.SetExtension("newBuyer", ExtensionEngineKind_BuiltIn)

	result, err := appDef.Build()

	t.Run("test results", func(t *testing.T) {
		require := require.New(t)
		require.NoError(err)
		require.NotNil(result)
	})

}
