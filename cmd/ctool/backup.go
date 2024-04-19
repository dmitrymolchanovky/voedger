/*
* Copyright (c) 2023-present Sigma-Soft, Ltd.
* @author Dmitry Molchanovsky
 */

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	coreutils "github.com/voedger/voedger/pkg/utils"

	"github.com/robfig/cron/v3"
)

var (
	expireTime           string
	jsonFormatBackupList bool
)

// nolint
func newBackupCmd() *cobra.Command {
	backupNodeCmd := &cobra.Command{
		Use:   "node [<node> <target folder>]",
		Short: "Backup db node",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return ErrInvalidNumberOfArguments
			}
			return nil
		},
		RunE: backupNode,
	}

	backupNodeCmd.PersistentFlags().StringVarP(&sshPort, "ssh-port", "p", "22", "SSH port")
	backupNodeCmd.PersistentFlags().StringVarP(&expireTime, "expire", "e", "", "Expire time for backup (e.g. 7d, 1m)")
	backupNodeCmd.PersistentFlags().StringVar(&sshKey, "ssh-key", "", "Path to SSH key")
	value, exists := os.LookupEnv(envVoedgerSshKey)
	if !exists || value == "" {
		if err := backupNodeCmd.MarkPersistentFlagRequired("ssh-key"); err != nil {
			loggerError(err.Error())
			return nil
		}
	}

	backupCronCmd := &cobra.Command{
		Use:   "cron [<cron event>]",
		Short: "Installation of a backup database of schedule",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return ErrInvalidNumberOfArguments
			}
			return nil
		},
		RunE: backupCron,
	}
	backupCronCmd.PersistentFlags().StringVar(&sshKey, "ssh-key", "", "Path to SSH key")
	value, exists = os.LookupEnv(envVoedgerSshKey)
	if !exists || value == "" {
		if err := backupCronCmd.MarkPersistentFlagRequired("ssh-key"); err != nil {
			loggerError(err.Error())
			return nil
		}
	}
	backupCronCmd.PersistentFlags().StringVarP(&expireTime, "expire", "e", "", "Expire time for backup (e.g. 7d, 1m)")

	backupListCmd := &cobra.Command{
		Use:   "list",
		Short: "Display a list of existing backups on all DB nodes",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return ErrInvalidNumberOfArguments
			}
			return nil
		},
		RunE: backupList,
	}
	backupListCmd.PersistentFlags().StringVar(&sshKey, "ssh-key", "", "Path to SSH key")
	if !exists || value == "" {
		if err := backupListCmd.MarkPersistentFlagRequired("ssh-key"); err != nil {
			loggerError(err.Error())
			return nil
		}
	}
	backupListCmd.PersistentFlags().BoolVar(&jsonFormatBackupList, "json", false, "Output in JSON format")

	backupNowCmd := &cobra.Command{
		Use:   "now",
		Short: "Backup database",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return ErrInvalidNumberOfArguments
			}
			return nil
		},
		RunE: backupNow,
	}

	backupNowCmd.PersistentFlags().StringVar(&sshKey, "ssh-key", "", "Path to SSH key")
	if !exists || value == "" {
		if err := backupNowCmd.MarkPersistentFlagRequired("ssh-key"); err != nil {
			loggerError(err.Error())
			return nil
		}
	}

	backupCmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup database",
	}

	backupCmd.AddCommand(backupNodeCmd, backupCronCmd, backupListCmd, backupNowCmd)

	return backupCmd

}

type expireType struct {
	value int
	unit  string
}

func (e *expireType) validate() error {
	if e.unit != "d" && e.unit != "m" {
		return ErrInvalidExpireTime
	}

	if e.value <= 0 {
		return ErrInvalidExpireTime
	}

	return nil
}

func (e *expireType) string() string {
	return fmt.Sprintf("%d%s", e.value, e.unit)
}

func newExpireType(str string) (*expireType, error) {
	unit := string(str[len(str)-1])
	valueStr := str[:len(str)-1]
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return nil, ErrInvalidExpireTime
	}

	expire := &expireType{
		value: value,
		unit:  unit,
	}

	if err := expire.validate(); err != nil {
		return nil, err
	}

	return expire, nil
}

// nolint
func validateBackupCronCmd(cmd *cmdType, cluster *clusterType) error {

	if len(cmd.Args) != 2 {
		return ErrInvalidNumberOfArguments
	}

	if _, err := cron.ParseStandard(cmd.Args[1]); err != nil {
		return err
	}

	return nil
}

// nolint
func validateBackupNodeCmd(cmd *cmdType, cluster *clusterType) error {

	if len(cmd.Args) != 4 {
		return ErrInvalidNumberOfArguments
	}

	var err error

	if n := cluster.nodeByHost(cmd.Args[1]); n == nil {
		err = errors.Join(err, fmt.Errorf(errHostNotFoundInCluster, cmd.Args[1], ErrHostNotFoundInCluster))
	}

	exists, errExists := coreutils.Exists(cmd.Args[3])
	if errExists != nil {
		// notest
		err = errors.Join(err, errExists)
		return err
	}
	if !exists {
		err = errors.Join(err, fmt.Errorf(errSshKeyNotFound, cmd.Args[3], ErrFileNotFound))
	}

	return err
}

func newBackupErrorEvent(host string, err error) *eventType {
	return &eventType{
		StartsAt: customTime(time.Now()),
		EndsAt:   customTime(time.Now().Add(time.Minute)),
		Annotations: map[string]string{
			"backup": "Backup failed",
			"error":  err.Error(),
		},
		Labels: map[string]string{
			alertLabelSource:   "ctool",
			alertLabelInstance: host,
			alertLabelSeverity: "error",
		},
		GeneratorURL: "http://app-node-1:9093"}
}

func backupNode(cmd *cobra.Command, args []string) error {
	cluster := newCluster()

	var err error

	host := args[0]

	if err = mkCommandDirAndLogFile(cmd, cluster); err != nil {
		if e := newBackupErrorEvent(host, err).postAlert(cluster); e != nil {
			err = errors.Join(err, e)
		}
		return err
	}

	if expireTime != "" {
		expire, e := newExpireType(expireTime)
		if e != nil {
			if err := newBackupErrorEvent(host, e).postAlert(cluster); err != nil {
				e = errors.Join(err, e)
			}
			return e
		}
		cluster.Cron.ExpireTime = expire.string()
	}

	loggerInfo("Backup node", strings.Join(args, " "))
	if err = newScriptExecuter(cluster.sshKey, "").
		run("backup-node.sh", args...); err != nil {
		if e := newBackupErrorEvent(host, err).postAlert(cluster); e != nil {
			err = errors.Join(err, e)
		}
		return err
	}

	if err = deleteExpireBacups(cluster, args[0]); err != nil {
		return err
	}

	return nil
}

func newBackupFolderName() string {
	t := time.Now()
	formattedDate := t.Format("20060102150405")
	return filepath.Join(backupFolder, fmt.Sprintf("%s-backup", formattedDate))
}

func backupNow(cmd *cobra.Command, args []string) error {
	cluster := newCluster()

	if cluster.Draft {
		return ErrClusterConfNotFound
	}

	var err error

	if err = mkCommandDirAndLogFile(cmd, cluster); err != nil {
		return err
	}

	if err = checkBackupFolders(cluster); err != nil {
		return err
	}

	folder := newBackupFolderName()

	for _, n := range cluster.Nodes {
		if n.NodeRole != nrDBNode {
			continue
		}

		loggerInfo("Backup node", n.nodeName(), n.address())
		if err = newScriptExecuter(cluster.sshKey, "").
			run("backup-node.sh", n.address(), folder); err != nil {
			return err
		}
	}
	return nil
}

func backupCron(cmd *cobra.Command, args []string) error {
	cluster := newCluster()
	if cluster.Draft {
		return ErrClusterConfNotFound
	}

	if expireTime != "" {
		expire, err := newExpireType(expireTime)
		if err != nil {
			return err
		}
		cluster.Cron.ExpireTime = expire.string()
	}

	Cmd := newCmd(ckBackup, append([]string{"cron"}, args...))

	var err error

	if err = Cmd.validate(cluster); err != nil {
		return err
	}

	if err = mkCommandDirAndLogFile(cmd, cluster); err != nil {
		return err
	}

	if err = checkBackupFolders(cluster); err != nil {
		return err
	}

	if err = setCronBackup(cluster, args[0]); err != nil {
		return err
	}

	loggerInfoGreen("Cron schedule set successfully")

	cluster.Cron.Backup = args[0]
	if err = cluster.saveToJSON(); err != nil {
		return err
	}

	return nil
}

// Checking the presence of a Backup folder on DBNodes
func checkBackupFolders(cluster *clusterType) error {
	var err error
	for _, n := range cluster.Nodes {
		if n.NodeRole == nrDBNode {
			if e := newScriptExecuter(cluster.sshKey, "").
				run("check-remote-folder.sh", n.address(), backupFolder); e != nil {
				err = errors.Join(err, fmt.Errorf(errBackupFolderIsNotPrepared, n.nodeName()+" "+n.address(), ErrBackupFolderIsNotPrepared))
			}
		}
	}
	return err
}

// Checking the presence of a Backup folder on node
func checkBackupFolderOnHost(cluster *clusterType, addr string) error {
	if e := newScriptExecuter(cluster.sshKey, "").
		run("check-remote-folder.sh", addr, backupFolder); e != nil {
		return fmt.Errorf(errBackupFolderIsNotPrepared, addr, ErrBackupFolderIsNotPrepared)
	}
	return nil
}

func backupList(cmd *cobra.Command, args []string) error {
	cluster := newCluster()
	if cluster.Draft {
		return ErrClusterConfNotFound
	}

	var err error

	if err = mkCommandDirAndLogFile(cmd, cluster); err != nil {
		return err
	}

	if err = checkBackupFolders(cluster); err != nil {
		return err
	}

	backups, err := getBackupList(cluster)

	loggerInfo(backups)

	return err
}

func getBackupList(cluster *clusterType) (string, error) {

	backupFName := filepath.Join(scriptsTempDir, "backups.lst")

	err := os.Remove(backupFName)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	args := []string{}
	if jsonFormatBackupList {
		args = []string{"json"}
	}

	if err = newScriptExecuter(cluster.sshKey, "").run("backup-list.sh", args...); err != nil {
		return "", nil
	}

	fContent, e := os.ReadFile(backupFName)
	if e != nil {
		return "", e
	}

	return string(fContent), nil
}

func deleteExpireBacups(cluster *clusterType, hostAddr string) error {

	if cluster.Cron.ExpireTime == "" {
		return nil
	}

	loggerInfo("Search and delete expire backups on", hostAddr)
	if err := newScriptExecuter(cluster.sshKey, "").
		run("delete-expire-backups-ssh.sh", hostAddr, backupFolder, cluster.Cron.ExpireTime); err != nil {
		return err
	}

	return nil
}
