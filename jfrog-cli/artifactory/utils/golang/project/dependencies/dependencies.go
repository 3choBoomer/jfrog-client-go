package dependencies

import (
	"bytes"
	"fmt"
	"github.com/jfrog/jfrog-cli-go/jfrog-cli/artifactory/utils"
	golangutil "github.com/jfrog/jfrog-cli-go/jfrog-cli/artifactory/utils/golang"
	"github.com/jfrog/jfrog-cli-go/jfrog-cli/utils/config"
	"github.com/jfrog/jfrog-cli-go/jfrog-client/artifactory/buildinfo"
	"github.com/jfrog/jfrog-cli-go/jfrog-client/artifactory/services/vgo"
	"github.com/jfrog/jfrog-cli-go/jfrog-client/utils/errorutils"
	"github.com/jfrog/jfrog-cli-go/jfrog-client/utils/io/fileutils"
	"github.com/jfrog/jfrog-cli-go/jfrog-client/utils/io/fileutils/checksum"
	"github.com/jfrog/jfrog-cli-go/jfrog-client/utils/log"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

func Load() ([]Dependency, error) {
	goPath, err := getGOPATH()
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	cachePath := filepath.Join(goPath, "src", "v", "cache")
	return getDependencies(cachePath)
}

// Represent vgo dependency project.
// Includes publishing capabilities and build info dependencies.
type Dependency struct {
	buildInfoDependencies []buildinfo.Dependency
	id                    string
	modContent            []byte
	zipPath               string
	version               string
}

func (dependency *Dependency) GetId() string {
	return dependency.id
}

func (dependency *Dependency) Publish(targetRepo string, details *config.ArtifactoryDetails) error {
	log.Info("Publishing:", dependency.id, "to", targetRepo)
	servicesManager, err := utils.CreateServiceManager(details, false)
	if err != nil {
		return err
	}
	params := &vgo.VgoParamsImpl{}
	params.ZipPath = dependency.zipPath
	params.ModContent = dependency.modContent
	params.Version = dependency.version
	params.TargetRepo = targetRepo

	return servicesManager.PublishVgoProject(params)
}

func (dependency *Dependency) Dependencies() []buildinfo.Dependency {
	return dependency.buildInfoDependencies
}

func getDependencies(cachePath string) ([]Dependency, error) {
	vgoCmd, err := golangutil.NewCmd()
	if err != nil {
		return nil, err
	}
	vgoCmd.Command = []string{"list"}
	vgoCmd.CommandFlags = []string{"-m"}
	output, err := utils.RunCmdOutput(vgoCmd)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}

	nameVersionMap, err := parseListOutput(output)
	if err != nil {
		return nil, nil
	}

	deps := []Dependency{}
	for name, ver := range nameVersionMap {
		dep, err := createDependency(cachePath, name, ver)
		if err != nil {
			return nil, err
		}
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	return deps, nil
}

// Creates a vgo dependency.
// Returns a nil value in case the dependency does not include a zip in the cache.
func createDependency(cachePath, dependencyName, version string) (*Dependency, error) {
	// We first check if the this dependency has a zip binary in the local vgo cache.
	// If it does not, nil is returned. This seems to be a bug in vgo.
	zipPath := filepath.Join(cachePath, dependencyName, "@v", version+".zip")
	fileExists, err := fileutils.IsFileExists(zipPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Could not find zip binary for dependency '%s' at %s.", dependencyName, zipPath))
		return nil, err
	}
	// Zip binary does not exist, so we skip it by returning a nil dependency.
	if !fileExists {
		return nil, nil
	}

	dep := Dependency{}

	dep.id = strings.Join([]string{dependencyName, version}, ":")
	dep.version = version
	dep.zipPath = zipPath
	dep.modContent, err = ioutil.ReadFile(filepath.Join(cachePath, dependencyName, "@v", version+".mod"))
	if err != nil {
		return &dep, errorutils.CheckError(err)
	}

	// Mod file dependency
	modDependency := buildinfo.Dependency{Id: dep.id}
	checksums, err := checksum.Calc(bytes.NewBuffer(dep.modContent))
	if err != nil {
		return &dep, err
	}
	modDependency.Checksum = &buildinfo.Checksum{Sha1: checksums[checksum.SHA1], Md5: checksums[checksum.MD5]}

	// Zip file dependency
	zipDependency := buildinfo.Dependency{Id: dep.id}
	fileDetails, err := fileutils.GetFileDetails(dep.zipPath)
	if err != nil {
		return &dep, err
	}
	zipDependency.Checksum = &buildinfo.Checksum{Sha1: fileDetails.Checksum.Sha1, Md5: fileDetails.Checksum.Md5}

	dep.buildInfoDependencies = append(dep.buildInfoDependencies, modDependency, zipDependency)
	return &dep, nil
}

func parseListOutput(content []byte) (map[string]string, error) {
	depRegexp, err := regexp.Compile("(\\S+)\\s+(\\S+)")
	if err != nil {
		return nil, errorutils.CheckError(err)
	}

	depMap := map[string]string{}
	lines := bytes.Split(content, []byte("\n"))
	for i := 2; i < len(lines); i++ {
		dependency := depRegexp.FindStringSubmatch(string(lines[i]))
		if len(dependency) == 3 {
			depMap[dependency[1]] = dependency[2]
		}
	}
	return depMap, nil
}

func getGOPATH() (string, error) {
	vgoCmd, err := golangutil.NewCmd()
	if err != nil {
		return "", err
	}
	vgoCmd.Command = []string{"env", "GOPATH"}
	output, err := utils.RunCmdOutput(vgoCmd)
	if err != nil {
		return "", fmt.Errorf("Could not find GOPATH env: %s", err.Error())
	}
	return strings.TrimSpace(string(output)), nil
}
