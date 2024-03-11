/*
* Copyright (c) 2024-present Sigma-Soft, Ltd.
* @author Dmitry Molchanovsky
 */

package main

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

func newPrometheusCmd() *cobra.Command {
	prometheusAdminPasswordCmd := &cobra.Command{
		Use:   "admin-password <password>",
		Short: "Set admin password for prometheus",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return ErrInvalidNumberOfArguments
			}
			return nil
		},
		RunE: prometheusAdminPassword,
	}

	prometheusAdminPasswordCmd.PersistentFlags().StringVar(&sshKey, "ssh-key", "", "Path to SSH key")
	value, exists := os.LookupEnv(envVoedgerSshKey)
	if !exists || value == "" {
		if err := prometheusAdminPasswordCmd.MarkPersistentFlagRequired("ssh-key"); err != nil {
			loggerError(err.Error())
			return nil
		}
	}

	prometheusCmd := &cobra.Command{
		Use:   "prometheus",
		Short: "Prometheus management",
	}

	prometheusCmd.AddCommand(prometheusAdminPasswordCmd)

	return prometheusCmd

}

func prometheusAdminPassword(cmd *cobra.Command, args []string) error {
	cluster := newCluster()
	if cluster.Draft {
		return ErrClusterConfNotFound
	}

	password := args[0]

	if err := setPrometheusAdminPassword(cluster, password, []string{"app-node-1", "app-node-2"}); err != nil {
		return err
	}

	loggerInfoGreen("Password for the admin user in Prometheus was successfully changed")

	return nil
}

func hashedPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func checkPrometheusPassword(password string) error {
	if len(password) < minPrometheusPasswordLength {
		return ErrPrometheusPasswordIsTooShort
	}
	return nil
}

func setPrometheusAdminPassword(cluster *clusterType, password string, hosts []string) error {
	if err := checkPrometheusPassword(password); err != nil {
		return err
	}

	hash, err := hashedPassword(password)
	if err != nil {
		return err
	}

	args := append([]string{password, hash}, hosts...)

	return newScriptExecuter(cluster.sshKey, "").
		run("prometheus-admin-password.sh", args...)
}
