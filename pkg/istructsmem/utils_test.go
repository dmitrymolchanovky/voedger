/*
 * Copyright (c) 2021-present Sigma-Soft, Ltd.
 * @author: Nikolay Nikitin
 */

package istructsmem

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/voedger/voedger/pkg/appdef"
	"github.com/voedger/voedger/pkg/irates"
	"github.com/voedger/voedger/pkg/iratesce"
	"github.com/voedger/voedger/pkg/istructs"
	"github.com/voedger/voedger/pkg/istructsmem/internal/consts"
)

func Test_splitID(t *testing.T) {
	tests := []struct {
		name    string
		id      uint64
		wantHi  uint64
		wantLow uint16
	}{
		{
			name:    "split null record must return zeros",
			id:      uint64(istructs.NullRecordID),
			wantHi:  0,
			wantLow: 0,
		},
		{
			name:    "split 4095 must return 0 and 4095",
			id:      4095,
			wantHi:  0,
			wantLow: 4095,
		},
		{
			name:    "split 4096 must return 1 and 0",
			id:      4096,
			wantHi:  1,
			wantLow: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHi, gotLow := crackID(tt.id)
			if gotHi != tt.wantHi {
				t.Errorf("splitID() got Hi = %v, want %v", gotHi, tt.wantHi)
			}
			if gotLow != tt.wantLow {
				t.Errorf("splitID() got Low = %v, want %v", gotLow, tt.wantLow)
			}
		})
	}
}

func Test_recordKey(t *testing.T) {
	const ws = istructs.WSID(0xa1a2a3a4a5a6a7a8)
	pkPref := []byte{0, byte(consts.SysView_Records), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	tests := []struct {
		name   string
		id     istructs.RecordID
		wantPk []byte
		wantCc []byte
	}{
		{
			name:   "null record must return {0} and {0}",
			id:     istructs.NullRecordID,
			wantPk: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			wantCc: []byte{0, 0},
		},
		{
			name:   "4095 must return {0} and {0x0F, 0xFF}",
			id:     istructs.RecordID(4095),
			wantPk: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			wantCc: []byte{0x0F, 0xFF},
		},
		{
			name:   "4096 must return {1} and {0}",
			id:     istructs.RecordID(4096),
			wantPk: []byte{0, 0, 0, 0, 0, 0, 0, 1},
			wantCc: []byte{0, 0},
		},
		{
			name:   "4097 must return {1} and {1}",
			id:     istructs.RecordID(4097),
			wantPk: []byte{0, 0, 0, 0, 0, 0, 0, 1},
			wantCc: []byte{0, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPk, gotCc := recordKey(ws, tt.id)
			wantPk := append(pkPref, tt.wantPk...)
			if !reflect.DeepEqual(gotPk, wantPk) {
				t.Errorf("splitRecordID() gotPk = %v, want %v", gotPk, tt.wantPk)
			}
			if !reflect.DeepEqual(gotCc, tt.wantCc) {
				t.Errorf("splitRecordID() gotCc = %v, want %v", gotCc, tt.wantCc)
			}
		})
	}
}

func TestObjectFillAndGet(t *testing.T) {
	require := require.New(t)
	test := test()

	cfgs := test.AppConfigs
	asp := Provide(cfgs, iratesce.TestBucketsFactory, testTokensFactory(), simpleStorageProvider())
	_, err := asp.AppStructs(test.appName)
	require.NoError(err)
	builder := NewIObjectBuilder(cfgs[istructs.AppQName_test1_app1], test.testCDoc)

	t.Run("basic", func(t *testing.T) {

		data := map[string]interface{}{
			"sys.ID":  float64(7),
			"int32":   float64(1),
			"int64":   float64(2),
			"float32": float64(3),
			"float64": float64(4),
			"bytes":   "BQY=", // []byte{5,6}
			"string":  "str",
			"QName":   "test.CDoc",
			"bool":    true,
			"record": []interface{}{
				map[string]interface{}{
					"sys.ID": float64(8),
					"int32":  float64(6),
				},
			},
		}
		cfg := cfgs[test.appName]
		require.NoError(FillObjectFromJSON(data, cfg.AppDef.Type(test.testCDoc), builder))
		o, err := builder.Build()
		require.NoError(err)

		require.Equal(istructs.RecordID(7), o.AsRecordID("sys.ID"))
		require.Equal(int32(1), o.AsInt32("int32"))
		require.Equal(int64(2), o.AsInt64("int64"))
		require.Equal(float32(3), o.AsFloat32("float32"))
		require.Equal(float64(4), o.AsFloat64("float64"))
		require.Equal([]byte{5, 6}, o.AsBytes("bytes"))
		require.Equal("str", o.AsString("string"))
		require.Equal(test.testCDoc, o.AsQName("QName"))
		require.True(o.AsBool("bool"))
		count := 0
		o.Children("record", func(c istructs.IObject) {
			require.Equal(istructs.RecordID(8), c.AsRecordID("sys.ID"))
			require.Equal(int32(6), c.AsInt32("int32"))
			count++
		})
		require.Equal(1, count)
	})

	t.Run("type errors", func(t *testing.T) {
		cases := map[string]interface{}{
			"int32":   "str",
			"int64":   "str",
			"float32": "str",
			"float64": "str",
			"bytes":   float64(2),
			"string":  float64(3),
			"QName":   float64(4),
			"bool":    "str",
			"record": []interface{}{
				map[string]interface{}{"int32": "str"},
			},
		}

		cfg := cfgs[test.appName]
		for name, val := range cases {
			builder := NewIObjectBuilder(cfgs[istructs.AppQName_test1_app1], test.testCDoc)
			data := map[string]interface{}{
				"sys.ID": float64(1),
				name:     val,
			}
			require.NoError(FillObjectFromJSON(data, cfg.AppDef.Type(test.testCDoc), builder))
			o, err := builder.Build()
			require.ErrorIs(err, ErrWrongFieldType)
			require.Nil(o)
		}
	})

	t.Run("container errors", func(t *testing.T) {
		builder := NewIObjectBuilder(cfgs[istructs.AppQName_test1_app1], test.testCDoc)
		cases := []struct {
			f string
			v interface{}
		}{
			{"unknownContainer", []interface{}{}},
			{"record", []interface{}{"str"}},
			{"record", []interface{}{map[string]interface{}{"unknownContainer": []interface{}{}}}},
		}
		cfg := cfgs[test.appName]
		for _, c := range cases {
			data := map[string]interface{}{
				c.f: c.v,
			}
			err := FillObjectFromJSON(data, cfg.AppDef.Type(test.testCDoc), builder)
			require.Error(err)
		}
	})
}

func TestIBucketsFromIAppStructs(t *testing.T) {
	require := require.New(t)

	cfgs := AppConfigsType{}
	cfg := cfgs.AddConfig(istructs.AppQName_test1_app1, appdef.New())
	funcQName := appdef.NewQName("my", "func")
	rlExpected := istructs.RateLimit{
		Period:                1,
		MaxAllowedPerDuration: 2,
	}
	cfg.FunctionRateLimits.AddAppLimit(funcQName, rlExpected)
	asp := Provide(cfgs, iratesce.TestBucketsFactory, testTokensFactory(), simpleStorageProvider())
	as, err := asp.AppStructs(istructs.AppQName_test1_app1)
	require.NoError(err)
	buckets := IBucketsFromIAppStructs(as)
	bsActual, err := buckets.GetDefaultBucketsState(GetFunctionRateLimitName(funcQName, istructs.RateLimitKind_byApp))
	require.NoError(err)
	require.Equal(rlExpected.Period, bsActual.Period)
	require.Equal(irates.NumTokensType(rlExpected.MaxAllowedPerDuration), bsActual.MaxTokensPerPeriod)
}
