// Code generated by "stringer -type=ProjectorEventKind -output=stringer_projectoreventkind.go"; DO NOT EDIT.

package appdef

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ProjectorEventKind_Insert-1]
	_ = x[ProjectorEventKind_Update-2]
	_ = x[ProjectorEventKind_Activate-3]
	_ = x[ProjectorEventKind_Deactivate-4]
	_ = x[ProjectorEventKind_Execute-5]
	_ = x[ProjectorEventKind_ExecuteWithParam-6]
	_ = x[ProjectorEventKind_Count-7]
}

const _ProjectorEventKind_name = "ProjectorEventKind_InsertProjectorEventKind_UpdateProjectorEventKind_ActivateProjectorEventKind_DeactivateProjectorEventKind_ExecuteProjectorEventKind_ExecuteWithParamProjectorEventKind_Count"

var _ProjectorEventKind_index = [...]uint8{0, 25, 50, 77, 106, 132, 167, 191}

func (i ProjectorEventKind) String() string {
	i -= 1
	if i >= ProjectorEventKind(len(_ProjectorEventKind_index)-1) {
		return "ProjectorEventKind(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ProjectorEventKind_name[_ProjectorEventKind_index[i]:_ProjectorEventKind_index[i+1]]
}