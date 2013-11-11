// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package lxc

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"launchpad.net/golxc"
	"launchpad.net/loggo"

	"launchpad.net/juju-core/container"
	"launchpad.net/juju-core/environs/cloudinit"
	"launchpad.net/juju-core/instance"
	"launchpad.net/juju-core/names"
	"launchpad.net/juju-core/utils"
)

var logger = loggo.GetLogger("juju.container.lxc")

var (
	defaultTemplate     = "ubuntu-cloud"
	aptHTTPProxyRE      = regexp.MustCompile(`(?i)^Acquire::HTTP::Proxy\s+"([^"]+)";$`)
	ContainerDir        = "/var/lib/juju/containers"
	RemovedContainerDir = "/var/lib/juju/removed-containers"
	LxcContainerDir     = "/var/lib/lxc"
	LxcRestartDir       = "/etc/lxc/auto"
	LxcObjectFactory    = golxc.Factory()
)

const (
	// DefaultLxcBridge is the package created container bridge
	DefaultLxcBridge = "lxcbr0"
)

// DefaultNetworkConfig returns a valid NetworkConfig to use the
// defaultLxcBridge that is created by the lxc package.
func DefaultNetworkConfig() *container.NetworkConfig {
	return container.BridgeNetworkConfig(DefaultLxcBridge)
}

type containerManager struct {
	name   string
	logdir string
}

// containerManager implements container.Manager.
var _ container.Manager = (*containerManager)(nil)

// NewContainerManager returns a manager object that can start and stop lxc
// containers. The containers that are created are namespaced by the name
// parameter.
func NewContainerManager(conf container.ManagerConfig) container.Manager {
	logdir := "/var/log/juju"
	if conf.LogDir != "" {
		logdir = conf.LogDir
	}
	return &containerManager{name: conf.Name, logdir: logdir}
}

func (manager *containerManager) StartContainer(
	machineConfig *cloudinit.MachineConfig,
	series string,
	network *container.NetworkConfig) (instance.Instance, error) {

	name := names.MachineTag(machineConfig.MachineId)
	if manager.name != "" {
		name = fmt.Sprintf("%s-%s", manager.name, name)
	}
	// Note here that the lxcObjectFacotry only returns a valid container
	// object, and doesn't actually construct the underlying lxc container on
	// disk.
	lxcContainer := LxcObjectFactory.New(name)

	// Create the cloud-init.
	directory := jujuContainerDirectory(name)
	logger.Tracef("create directory: %s", directory)
	if err := os.MkdirAll(directory, 0755); err != nil {
		logger.Errorf("failed to create container directory: %v", err)
		return nil, err
	}
	logger.Tracef("write cloud-init")
	userDataFilename, err := container.WriteUserData(machineConfig, directory)
	if err != nil {
		logger.Errorf("failed to write user data: %v", err)
		return nil, err
	}
	logger.Tracef("write the lxc.conf file")
	configFile, err := writeLxcConfig(network, directory, manager.logdir)
	if err != nil {
		logger.Errorf("failed to write config file: %v", err)
		return nil, err
	}
	templateParams := []string{
		"--debug",                      // Debug errors in the cloud image
		"--userdata", userDataFilename, // Our groovey cloud-init
		"--hostid", name, // Use the container name as the hostid
		"-r", series,
	}
	// Create the container.
	logger.Tracef("create the container")
	if err := lxcContainer.Create(configFile, defaultTemplate, templateParams...); err != nil {
		logger.Errorf("lxc container creation failed: %v", err)
		return nil, err
	}
	// Make sure that the mount dir has been created.
	logger.Tracef("make the mount dir for the shard logs")
	if err := os.MkdirAll(internalLogDir(name), 0755); err != nil {
		logger.Errorf("failed to create internal /var/log/juju mount dir: %v", err)
		return nil, err
	}
	logger.Tracef("lxc container created")
	// Now symlink the config file into the restart directory.
	containerConfigFile := filepath.Join(LxcContainerDir, name, "config")
	if err := os.Symlink(containerConfigFile, restartSymlink(name)); err != nil {
		return nil, err
	}
	logger.Tracef("auto-restart link created")

	// Start the lxc container with the appropriate settings for grabbing the
	// console output and a log file.
	consoleFile := filepath.Join(directory, "console.log")
	lxcContainer.SetLogFile(filepath.Join(directory, "container.log"), golxc.LogDebug)
	logger.Tracef("start the container")
	// We explicitly don't pass through the config file to the container.Start
	// method as we have passed it through at container creation time.  This
	// is necessary to get the appropriate rootfs reference without explicitly
	// setting it ourselves.
	if err = lxcContainer.Start("", consoleFile); err != nil {
		logger.Errorf("container failed to start: %v", err)
		return nil, err
	}
	logger.Tracef("container started")
	return &lxcInstance{lxcContainer, name}, nil
}

func (manager *containerManager) StopContainer(instance instance.Instance) error {
	name := string(instance.Id())
	container := LxcObjectFactory.New(name)
	// Remove the autostart link.
	if err := os.Remove(restartSymlink(name)); err != nil {
		logger.Errorf("failed to remove restart symlink: %v", err)
		return err
	}
	if err := container.Destroy(); err != nil {
		logger.Errorf("failed to destroy lxc container: %v", err)
		return err
	}

	// Move the directory.
	logger.Tracef("create old container dir: %s", RemovedContainerDir)
	if err := os.MkdirAll(RemovedContainerDir, 0755); err != nil {
		logger.Errorf("failed to create removed container directory: %v", err)
		return err
	}
	removedDir, err := uniqueDirectory(RemovedContainerDir, name)
	if err != nil {
		logger.Errorf("was not able to generate a unique directory: %v", err)
		return err
	}
	if err := os.Rename(jujuContainerDirectory(name), removedDir); err != nil {
		logger.Errorf("failed to rename container directory: %v", err)
		return err
	}
	return nil
}

func (manager *containerManager) ListContainers() (result []instance.Instance, err error) {
	containers, err := LxcObjectFactory.List()
	if err != nil {
		logger.Errorf("failed getting all instances: %v", err)
		return
	}
	managerPrefix := ""
	if manager.name != "" {
		managerPrefix = fmt.Sprintf("%s-", manager.name)
	}

	for _, container := range containers {
		// Filter out those not starting with our name.
		name := container.Name()
		if !strings.HasPrefix(name, managerPrefix) {
			continue
		}
		if container.IsRunning() {
			result = append(result, &lxcInstance{container, name})
		}
	}
	return
}

func jujuContainerDirectory(containerName string) string {
	return filepath.Join(ContainerDir, containerName)
}

const internalLogDirTemplate = "%s/%s/rootfs/var/log/juju"

func internalLogDir(containerName string) string {
	return fmt.Sprintf(internalLogDirTemplate, LxcContainerDir, containerName)
}

func restartSymlink(name string) string {
	return filepath.Join(LxcRestartDir, name+".conf")
}

const localConfig = `%s
lxc.mount.entry=%s var/log/juju none defaults,bind 0 0
`

const networkTemplate = `
lxc.network.type = %s
lxc.network.link = %s
lxc.network.flags = up
`

func networkConfigTemplate(networkType, networkLink string) string {
	return fmt.Sprintf(networkTemplate, networkType, networkLink)
}

func generateNetworkConfig(network *container.NetworkConfig) string {
	if network == nil {
		logger.Warningf("network unspecified, using default networking config")
		network = DefaultNetworkConfig()
	}
	switch network.NetworkType {
	case container.PhysicalNetwork:
		return networkConfigTemplate("phys", network.Device)
	default:
		logger.Warningf("Unknown network config type %q: using bridge", network.NetworkType)
		fallthrough
	case container.BridgeNetwork:
		return networkConfigTemplate("veth", network.Device)
	}
}

func writeLxcConfig(network *container.NetworkConfig, directory, logdir string) (string, error) {
	networkConfig := generateNetworkConfig(network)
	configFilename := filepath.Join(directory, "lxc.conf")
	configContent := fmt.Sprintf(localConfig, networkConfig, logdir)
	if err := ioutil.WriteFile(configFilename, []byte(configContent), 0644); err != nil {
		return "", err
	}
	return configFilename, nil
}

// uniqueDirectory returns "path/name" if that directory doesn't exist.  If it
// does, the method starts appending .1, .2, etc until a unique name is found.
func uniqueDirectory(path, name string) (string, error) {
	dir := filepath.Join(path, name)
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return dir, nil
	}
	for i := 1; ; i++ {
		dir := filepath.Join(path, fmt.Sprintf("%s.%d", name, i))
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return dir, nil
		} else if err != nil {
			return "", err
		}
	}
}
