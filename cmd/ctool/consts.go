/*
* Copyright (c) 2023-present Sigma-Soft, Ltd.
* @author Dmitry Molchanovsky
 */

package main

// nolint
const (
	// edition types
	clusterEditionCE = "CE"
	clusterEditionSE = "SE"

	// name of the cluster configuration file
	clusterConfFileName  = "cluster.json"
	scyllaConfigFileName = "scylla.yaml"

	shellLib = "utils.sh"

	// node fail version
	nodeFailVersion = "fail"

	// Deploy SE args
	deploySeFirstNodeArgIdx = 1
	initSeArgCount          = 5
	seNodeCount             = 2
	dbNodeCount             = 3

	// Deploy SE args
	initCeArgCount = 1

	// DB node offset in cluster node list
	dbNodeOffset = 2

	// node Roles
	nrCENode  = "CENode"
	nrAppNode = "AppNode"
	nrDBNode  = "DBNode"

	embedScriptsDir = "scripts"

	dryRunDir = ".dry-run"
)

const (
	// aliases for indexes of SE cluster nodes
	idxSENode1 = int32(iota)
	idxSENode2
	idxDBNode1
	idxDBNode2
	idxDBNode3
)

const (
	// command kind
	ckInit    = "init"
	ckUpgrade = "upgrade"
	ckReplace = "replace"
	ckBackup  = "backup"
	ckAcme    = "acme"

	// minimum amount of RAM per node in MB
	minRamOnAppNode = "8192"
	minRamOnDBNode  = "8192"
	minRamCENode    = "8192"

	swarmDbmsLabelKey = "dbm"
	swarmAppLabelKey  = "app"
	swarmMonLabelKey  = "mon"

	// Variable environment
	envVoedgerNodeSshPort = "VOEDGER_NODE_SSH_PORT"
	envVoedgerAcmeDomains = "VOEDGER_ACME_DOMAINS"
	envVoedgerSshKey      = "VOEDGER_SSH_KEY"

	minMonPasswordLength = 5
	monUserName          = "voedger"
	admin                = "admin"
	voedger              = "voedger"

	logFolder = "log"

	alertManagerConfigFile = "~/alertmanager/config.yml"
)

const comma = ","

// folder for DB backups
const backupFolder = "/mnt/backup/voedger/"

const (
	alertLabelSource   = "source"
	alertLabelInstance = "instance"
	alertLabelSeverity = "severity"
)
