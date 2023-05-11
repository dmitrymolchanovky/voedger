/*
 * Copyright (c) 2023-present unTill Pro, Ltd.
 */

package sys_it

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/voedger/voedger/pkg/istructs"
	"github.com/voedger/voedger/pkg/sys/invite"
	coreutils "github.com/voedger/voedger/pkg/utils"
	it "github.com/voedger/voedger/pkg/vit"
)

func TestInvite_BasicUsage(t *testing.T) {
	//TODO Daniil fix it
	t.Skip("Daniil fix it https://dev.untill.com/projects/#!639145")
	require := require.New(t)
	vit := it.NewVIT(t, &it.SharedConfig_Simple)
	defer vit.TearDown()
	wsName := "test_ws"
	ws := vit.WS(istructs.AppQName_test1_app1, wsName)
	inviteEmailTemplate := "text:" + strings.Join([]string{
		invite.EmailTemplatePlaceholder_VerificationCode,
		invite.EmailTemplatePlaceholder_InviteID,
		invite.EmailTemplatePlaceholder_WSID,
		invite.EmailTemplatePlaceholder_WSName,
		invite.EmailTemplatePlaceholder_Email,
	}, ";")
	inviteEmailSubject := "you are invited"
	updateRolesEmailTemplate := "text:" + invite.EmailTemplatePlaceholder_Roles
	updateRolesEmailSubject := "your roles are updated"
	expireDatetime := vit.Now().UnixMilli()
	expireDatetimeStr := strconv.FormatInt(expireDatetime, 10)
	verificationCode := expireDatetimeStr[len(expireDatetimeStr)-6:]
	initialRoles := "initial.Roles"
	updatedRoles := "updated.Roles"

	initiateInvitationByEMail := func(email string) (inviteID int64) {
		body := fmt.Sprintf(`{"args":{"Email":"%s","Roles":"%s","ExpireDatetime":%d,"EmailTemplate":"%s","EmailSubject":"%s"}}`, email, initialRoles, expireDatetime, inviteEmailTemplate, inviteEmailSubject)
		return vit.PostWS(ws, "c.sys.InitiateInvitationByEMail", body).NewID()
	}

	initiateJoinWorkspace := func(inviteID int64, login string) {
		profile := vit.GetPrincipal(istructs.AppQName_test1_app1, login)
		vit.PostWS(ws, "c.sys.InitiateJoinWorkspace", fmt.Sprintf(`{"args":{"InviteID":%d,"VerificationCode":"%s"}}`, inviteID, verificationCode), coreutils.WithAuthorizeBy(profile.Token))
	}

	initiateUpdateInviteRoles := func(inviteID int64) {
		vit.PostWS(ws, "c.sys.InitiateUpdateInviteRoles", fmt.Sprintf(`{"args":{"InviteID":%d,"Roles":"%s","EmailTemplate":"%s","EmailSubject":"%s"}}`, inviteID, updatedRoles, updateRolesEmailTemplate, updateRolesEmailSubject))
	}

	waitForInviteState := func(inviteState int32, inviteID int64) {
		deadline := time.Now().Add(time.Second * 5)
		var entity []interface{}
		for time.Now().Before(deadline) {
			entity = vit.PostWS(ws, "q.sys.Collection", fmt.Sprintf(`
			{"args":{"Schema":"sys.Invite"},
			"elements":[{"fields":["State","sys.ID"]}],
			"filters":[{"expr":"eq","args":{"field":"sys.ID","value":%d}}]}`, inviteID)).SectionRow(0)
			if inviteState == int32(entity[0].(float64)) {
				return
			}
		}
		panic(fmt.Sprintf("invite [%d] is not in required state [%d] it has state [%d]", inviteID, inviteState, int32(entity[0].(float64))))
	}

	findCDocInviteByID := func(inviteID int64) []interface{} {
		return vit.PostWS(ws, "q.sys.Collection", fmt.Sprintf(`
			{"args":{"Schema":"sys.Invite"},
			"elements":[{"fields":[
				"SubjectKind",
				"Login",
				"Email",
				"Roles",
				"ExpireDatetime",
				"VerificationCode",
				"State",
				"Created",
				"Updated",
				"SubjectID",
				"InviteeProfileWSID",
				"sys.ID"
			]}],
			"filters":[{"expr":"eq","args":{"field":"sys.ID","value":%d}}]}`, inviteID)).SectionRow(0)
	}

	findCDocSubjectByLogin := func(login string) []interface{} {
		return vit.PostWS(ws, "q.sys.Collection", fmt.Sprintf(`
			{"args":{"Schema":"sys.Subject"},
			"elements":[{"fields":[
				"Login",
				"SubjectKind",
				"Roles",
				"sys.ID",
				"sys.IsActive"
			]}],
			"filters":[{"expr":"eq","args":{"field":"Login","value":"%s"}}]}`, login)).SectionRow(0)
	}

	findCDocJoinedWorkspaceByInvitingWorkspaceWSIDAndLogin := func(invitingWorkspaceWSID istructs.WSID, login string) []interface{} {
		return vit.PostProfile(vit.GetPrincipal(istructs.AppQName_test1_app1, login), "q.sys.Collection", fmt.Sprintf(`
			{"args":{"Schema":"sys.JoinedWorkspace"},
			"elements":[{"fields":[
				"sys.ID",
				"sys.IsActive",
				"Roles",
				"InvitingWorkspaceWSID",
				"WSName"
			]}],
			"filters":[{"expr":"eq","args":{"field":"InvitingWorkspaceWSID","value":%d}}]}`, invitingWorkspaceWSID)).SectionRow(0)
	}

	//Invite existing users
	inviteID := initiateInvitationByEMail(it.TestEmail)
	inviteID2 := initiateInvitationByEMail(it.TestEmail2)
	inviteID3 := initiateInvitationByEMail(it.TestEmail3)

	waitForInviteState(invite.State_ToBeInvited, inviteID)
	waitForInviteState(invite.State_ToBeInvited, inviteID2)
	waitForInviteState(invite.State_ToBeInvited, inviteID3)

	cDocInvite := findCDocInviteByID(inviteID)

	require.Equal(it.TestEmail, cDocInvite[1])
	require.Equal(it.TestEmail, cDocInvite[2])
	require.Equal(initialRoles, cDocInvite[3])
	require.Equal(float64(expireDatetime), cDocInvite[4])
	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[7])
	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	//Check that emails were send
	require.Equal(verificationCode, strings.Split(vit.ExpectEmail().Capture().Body, ";")[0])
	require.Equal(verificationCode, strings.Split(vit.ExpectEmail().Capture().Body, ";")[0])

	message := vit.ExpectEmail().Capture()
	ss := strings.Split(message.Body, ";")
	require.Equal(inviteEmailSubject, message.Subject)
	require.Equal(invite.EmailFrom, message.From)
	require.Equal([]string{it.TestEmail3}, message.To)
	require.Equal(verificationCode, ss[0])
	require.Equal(strconv.FormatInt(inviteID3, 10), ss[1])
	require.Equal(strconv.FormatInt(int64(ws.WSID), 10), ss[2])
	require.Equal(wsName, ss[3])
	require.Equal(it.TestEmail3, ss[4])

	waitForInviteState(invite.State_Invited, inviteID)
	waitForInviteState(invite.State_Invited, inviteID2)
	waitForInviteState(invite.State_Invited, inviteID3)

	cDocInvite = findCDocInviteByID(inviteID2)

	require.Equal(verificationCode, cDocInvite[5])
	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	//Cancel then invite it again (inviteID3)
	vit.PostWS(ws, "c.sys.CancelSentInvite", fmt.Sprintf(`{"args":{"InviteID":%d}}`, inviteID3))
	waitForInviteState(invite.State_Cancelled, inviteID3)
	initiateInvitationByEMail(it.TestEmail3)
	waitForInviteState(invite.State_ToBeInvited, inviteID3)
	_ = vit.ExpectEmail().Capture()
	waitForInviteState(invite.State_Invited, inviteID3)

	//Join workspaces
	initiateJoinWorkspace(inviteID, it.TestEmail)
	initiateJoinWorkspace(inviteID2, it.TestEmail2)

	waitForInviteState(invite.State_ToBeJoined, inviteID)
	waitForInviteState(invite.State_ToBeJoined, inviteID2)

	cDocInvite = findCDocInviteByID(inviteID2)

	require.Equal(float64(vit.GetPrincipal(istructs.AppQName_test1_app1, it.TestEmail2).ProfileWSID), cDocInvite[10])
	require.Equal(float64(istructs.SubjectKind_User), cDocInvite[0])
	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	waitForInviteState(invite.State_Joined, inviteID)
	waitForInviteState(invite.State_Joined, inviteID2)

	cDocJoinedWorkspace := findCDocJoinedWorkspaceByInvitingWorkspaceWSIDAndLogin(ws.WSID, it.TestEmail2)

	require.Equal(initialRoles, cDocJoinedWorkspace[2])
	require.Equal(wsName, cDocJoinedWorkspace[4])

	cDocSubject := findCDocSubjectByLogin(it.TestEmail)

	require.Equal(it.TestEmail, cDocSubject[0])
	require.Equal(float64(istructs.SubjectKind_User), cDocSubject[1])
	require.Equal(initialRoles, cDocSubject[2])

	//Update roles
	initiateUpdateInviteRoles(inviteID)
	initiateUpdateInviteRoles(inviteID2)

	waitForInviteState(invite.State_ToUpdateRoles, inviteID)
	waitForInviteState(invite.State_ToUpdateRoles, inviteID2)

	cDocInvite = findCDocInviteByID(inviteID)

	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	//Check that emails were send
	require.Equal(updatedRoles, vit.ExpectEmail().Capture().Body)
	message = vit.ExpectEmail().Capture()
	require.Equal(updateRolesEmailSubject, message.Subject)
	require.Equal(invite.EmailFrom, message.From)
	require.Equal([]string{it.TestEmail2}, message.To)
	require.Equal(updatedRoles, message.Body)

	cDocSubject = findCDocSubjectByLogin(it.TestEmail2)

	require.Equal(updatedRoles, cDocSubject[2])

	//TODO Denis how to get WS by login? I want to check sys.JoinedWorkspace

	waitForInviteState(invite.State_Joined, inviteID)
	waitForInviteState(invite.State_Joined, inviteID2)

	//Cancel accepted invite
	vit.PostWS(ws, "c.sys.InitiateCancelAcceptedInvite", fmt.Sprintf(`{"args":{"InviteID":%d}}`, inviteID))

	waitForInviteState(invite.State_ToBeCancelled, inviteID)

	cDocInvite = findCDocInviteByID(inviteID)

	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	waitForInviteState(invite.State_Cancelled, inviteID)

	cDocSubject = findCDocSubjectByLogin(it.TestEmail)

	require.False(cDocSubject[4].(bool))

	cDocInvite = findCDocInviteByID(inviteID)

	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	//Leave workspace
	vit.PostWS(ws, "c.sys.InitiateLeaveWorkspace", "{}", coreutils.WithAuthorizeBy(vit.GetPrincipal(ws.Owner.AppQName, it.TestEmail2).Token))

	waitForInviteState(invite.State_ToBeLeft, inviteID2)

	cDocInvite = findCDocInviteByID(inviteID2)

	require.Equal(float64(vit.Now().UnixMilli()), cDocInvite[8])

	waitForInviteState(invite.State_Left, inviteID2)

	cDocSubject = findCDocSubjectByLogin(it.TestEmail2)

	require.False(cDocSubject[4].(bool))

	//TODO check InviteeProfile joined workspace
}

func TestCancelSentInvite(t *testing.T) {
	//TODO Fix it Daniil
	t.Skip("Fix it Daniil")
	//require := require.New(t)
	//vit := it.NewVIT(t, &it.SharedConfig_Simple)
	//defer vit.TearDown()
	//ws := vit.WS(istructs.AppQName_test1_app1, "test_ws")
	//
	//t.Run("Should be ok", func(t *testing.T) {
	//	body := `{"args":{"Email":"user@acme.com","Roles":"trolles","ExpireDatetime":1674751138000,"NewLoginEmailTemplate":"text:","ExistingLoginEmailTemplate":"text:"}}`
	//	inviteID := vit.PostWS(ws, "c.sys.InitiateInvitationByEMail", body).NewID()
	//	//Read it for successful vit tear down
	//	_ = vit.ExpectEmail().Capture()
	//
	//	vit.PostWS(ws, "c.sys.CancelSentInvite", fmt.Sprintf(`{"args":{"InviteID":%d}}`, inviteID))
	//})
	//t.Run("Should be not ok", func(t *testing.T) {
	//	resp := vit.PostWS(ws, "c.sys.CancelSentInvite", fmt.Sprintf(`{"args":{"InviteID":%d}}`, -100), coreutils.Expect400())
	//
	//	require.Equal(coreutils.NewHTTPError(http.StatusBadRequest, invite.errInviteNotExists), resp.SysError)
	//})
}
