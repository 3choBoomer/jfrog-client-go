# Overview
JFrog CLI is a compact and smart client that provides a simple interface that automates access to *Artifactory*, *Bintray* and *Mission Control* through their respective REST APIs.
By using the JFrog CLI, you can greatly simplify your automation scripts making them more readable and easier to maintain.
Several features of the JFrog CLI makes your scripts more efficient and reliable:

- Multi-threaded upload and download of artifacts make builds run faster
- Checksum optimization reduces redundant file transfers
- Wildcards and regular expressions give you an easy way to collect all the artifacts you wish to upload or download.
- "Dry run" gives you a preview of file transfer operations before you actually run them

# Download and Installation

You can get the executable directly from the [JFrog CLI Download Page](https://www.jfrog.com/getcli/), or you can download the source files from this GitHub project and build it yourself.

You can also [install JFrog CLI using NPM](https://www.npmjs.com/package/jfrog-cli-go) by running:
````
npm install jfrog-cli-go
````

and on Mac you can use:
````
brew install jfrog-cli-go
````

# Building the Executable

JFrog CLI is written in the [Go programming language](https://golang.org/), so to build the CLI yourself, you first need to have Go installed and configured on your machine.

## Install vgo

To download and install `vgo`, please refer to the [vgo documentation](https://github.com/golang/go/wiki/vgo).
Please use vgo version `2018-02-20.1` or above using `go get -u golang.org/x/vgo`.

With vgo the GOPATH environment variable can point to any folder where the vgo packages will be cached and used. Packages will appear in `$GOPATH/src/v`.
For vgo resolution set your GOPROXY to [repo.jfrog.org](https;//repo.jfrog.org) using `GOPROXY=https://repo.jfrog.org/artifctory/api/go/go`.

## Download and Build the CLI

To download and install the jfrog-cli-go project, execute the following commands:
````
git clone git@github.com:jfrog/jfrog-cli-go.git
cd jfrog-cli-go
vgo build -o jfrog
````
Once complete, you will find the JFrog CLI executable `jfrog` under the current directory.

# Tests

### Artifactory tests
#### General tests
To run Artifactory tests execute the following command: 
````
vgo test -v github.com/jfrog/jfrog-cli-go/jfrog-cli/jfrog
````
Optional flags:

| Flag | Description |
| --- | --- |
| `-rt.url` | [Default: http://localhost:8081/artifactory] Artifactory URL. |
| `-rt.user` | [Default: admin] Artifactory username. |
| `-rt.password` | [Default: password] Artifactory password. |
| `-rt.apikey` | [Optional] Artifactory API key. |
| `-rt.sshKeyPath` | [Optional] Ssh key file path. Should be used only if the Artifactory URL format is ssh://[domain]:port |
| `-rt.sshPassphrase` | [Optional] Ssh key passphrase. |


* Running the tests will create two repositories: `jfrog-cli-tests-repo` and `jfrog-cli-tests-repo1`.<br/>
  Once the tests are completed, the content of these repositories will be deleted.
  
#### Maven, Gradle and Npm tests
* The *M2_HOME* environment variable should be set to the local maven installation path.
* The *gradle* and *npm* executables pshould be included as part of the *PATH* environment variable.
* The *java* executable be included as part of the *PATH* environment variable. Alternatively, set the *JAVA_HOME* environment variable.

To run build tools tests execute the following command:
````
vgo test -v github.com/jfrog/jfrog-cli-go/jfrog-cli/jfrog -test.artifactory=false -test.buildTools=true
````
##### Limitation
* Currently, build integration support only http(s) connections to Artifactory using username and password.

#### Docker push test

To run docker push tests execute the following command (fill out the missing parameters as described below):
````
docker login
vgo test -v github.com/jfrog/jfrog-cli-go/jfrog-cli/jfrog -test.artifactory=false -test.docker=true -rt.dockerRepoDomain=DOCKER_DOMAIN -rt.dockerTargetRepo=DOCKER_TARGET_REPO -rt.url=ARTIFACTORY_URL -rt.user=USERNAME -rt.password=PASSWORD
````

##### Mandatory Parameters
| Flag | Description |
| --- | --- |
| `-rt.dockerRepoDomain` | Artifactory Docker registry domain. |
| `-rt.dockerTargetRepo` | Artifactory Docker repository name. |
| `-rt.url` | Artifactory URL. |
| `-rt.user` | Artifactory username. |
| `-rt.password` | Artifactory password. |

#### Vgo commands tests

To run vgo tests:
* Add vgo executable to the system search path (PATH environment variable).
* Run the following command:

````
vgo test -v github.com/jfrog/jfrog-cli-go/jfrog-cli/jfrog -test.artifactory=false -test.vgo=true 
````

### Bintray tests
Bintray tests credentials are taken from the CLI configuration. If non configured or not passed as flags, the tests will fail.

To run Bintray tests execute the following command: 
````
vgo test -v github.com/jfrog/jfrog-cli-go/jfrog-cli/jfrog -test.artifactory=false -test.bintray=true
````
Flags:

| Flag | Description |
| --- | --- |
| `-bt.user` | [Mandatory if not configured] Bintray username. |
| `-bt.key` | [Mandatory if not configured] Bintray API key. |
| `-bt.org` | [Optional] Bintray organization. If not configured, *-bt.user* is used as the organization name. |

* Running the tests will create a repository `jfrog-cli-tests-repo1` in bintray.<br/>
  Once the tests are completed, the repository will be deleted.

# Pull Requests
We welcome pull requests from the community.
## Guidelines
* Before creating your first pull request, please join our contributors community by signing [JFrog's CLA](https://secure.echosign.com/public/hostedForm?formid=5IYKLZ2RXB543N).
* Pull requests should be created on the *dev* branch.
* Please use [gofmt](https://golang.org/cmd/gofmt/) for formatting the code before submitting the pull request.

# Using JFrog CLI
JFrog CLI can be used for a variety of functions with Artifactory, Bintray, Xray and Mission Control,
and has a dedicated set of commands for each product.
To learn how to use JFrog CLI, please visit the [JFrog CLI User Guide](https://www.jfrog.com/confluence/display/CLI/Welcome+to+JFrog+CLI).

# Release Notes
The release are available on [Bintray](https://bintray.com/jfrog/jfrog-cli-go/jfrog-cli-linux-amd64#release).
