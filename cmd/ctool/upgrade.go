/*
* Copyright (c) 2023-present Sigma-Soft, Ltd.
* @author Dmitry Molchanovsky
 */

package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/untillpro/goutils/logger"
)

func newUpgradeCmd() *cobra.Command {
	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Update the cluster version to the current one",
		RunE:  upgrade,
	}

	upgradeCmd.PersistentFlags().StringVar(&sshKey, "ssh-key", "", "Path to SSH key")
	if err := upgradeCmd.MarkPersistentFlagRequired("ssh-key"); err != nil {
		logger.Error(err.Error())
		return nil
	}

	return upgradeCmd

}

// versions compare (version format: 0.0.1 or 0.0.1-alfa)
// return 1  if version1 > version2
// return -1 if version1 < version2
// return 0 if version1 = version2
func compareVersions(version1 string, version2 string) int {
	v1Components := strings.Split(version1, ".")
	v2Components := strings.Split(version2, ".")

	for i := 0; i < len(v1Components) || i < len(v2Components); i++ {
		v1 := 0
		v2 := 0

		if i < len(v1Components) {
			v1 = parseVersionComponent(v1Components[i])
		}
		if i < len(v2Components) {
			v2 = parseVersionComponent(v2Components[i])
		}

		if v1 > v2 {
			return 1
		} else if v1 < v2 {
			return -1
		}
	}

	return 0
}

func parseVersionComponent(component string) int {
	if strings.Contains(component, "-") {
		component = strings.Split(component, "-")[0]
	}
	var version int
	fmt.Sscanf(component, "%d", &version)
	return version
}

func upgrade(cmd *cobra.Command, args []string) error {

	cluster := newCluster()
	var err error

	err = mkCommandDirAndLogFile(cmd, cluster)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	ok, e := cluster.needUpgrade()
	if e != nil {
		logger.Error(e.Error())
		return e
	}

	if !ok {
		logger.Info(green("upgrade is not required"))
		return nil
	}

	c := newCmd(ckUpgrade, strings.Join(args, " "))
	defer func(cluster *clusterType) {
		err = cluster.saveToJSON()
		if err != nil {
			logger.Error(err.Error())
		}
	}(cluster)

	if err = cluster.applyCmd(c); err != nil {
		logger.Error(err.Error())
		return err
	}

	if err = cluster.Cmd.apply(cluster); err != nil {
		logger.Error(err)
		return err
	}

	return nil
}
