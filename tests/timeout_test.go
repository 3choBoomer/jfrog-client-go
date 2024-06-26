package tests

import (
	"github.com/3choboomer/jfrog-client-go/evidence"
	"github.com/3choboomer/jfrog-client-go/evidence/services"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/3choboomer/jfrog-client-go/access"
	accessAuth "github.com/3choboomer/jfrog-client-go/access/auth"
	"github.com/3choboomer/jfrog-client-go/artifactory"
	artifactoryAuth "github.com/3choboomer/jfrog-client-go/artifactory/auth"
	"github.com/3choboomer/jfrog-client-go/auth"
	"github.com/3choboomer/jfrog-client-go/config"
	"github.com/3choboomer/jfrog-client-go/distribution"
	"github.com/3choboomer/jfrog-client-go/lifecycle"
	"github.com/3choboomer/jfrog-client-go/pipelines"

	distributionAuth "github.com/3choboomer/jfrog-client-go/distribution/auth"
	distributionServices "github.com/3choboomer/jfrog-client-go/distribution/services"
	evidenceAuth "github.com/3choboomer/jfrog-client-go/evidence/auth"
	lifecycleAuth "github.com/3choboomer/jfrog-client-go/lifecycle/auth"
	lifecycleServices "github.com/3choboomer/jfrog-client-go/lifecycle/services"
	pipelinesAuth "github.com/3choboomer/jfrog-client-go/pipelines/auth"
	"github.com/3choboomer/jfrog-client-go/utils/log"
	"github.com/3choboomer/jfrog-client-go/utils/tests"
	"github.com/3choboomer/jfrog-client-go/xray"
	xrayAuth "github.com/3choboomer/jfrog-client-go/xray/auth"
	"github.com/stretchr/testify/assert"
)

const (
	overallRequestTimeout = time.Millisecond * 50
	handlerTimeout        = time.Millisecond * 100
)

func TestTimeout(t *testing.T) {
	previousLog := tests.RedirectLogOutputToNil()
	defer func() {
		log.SetLogger(previousLog)
	}()
	t.Run("testAccessTimeout", testAccessTimeout)
	t.Run("testArtifactoryTimeout", testArtifactoryTimeout)
	t.Run("testDistributionTimeout", testDistributionTimeout)
	t.Run("testLifecycleTimeout", testLifecycleTimeout)
	t.Run("testPipelinesTimeout", testPipelinesTimeout)
	t.Run("testXrayTimeout", testXrayTimeout)
	t.Run("testEvidenceTimeout", testEvidenceTimeout)
}

func testAccessTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := accessAuth.NewAccessDetails()
	details.SetUrl(url)
	servicesManager, err := access.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	// Expect timeout
	_, err = servicesManager.GetAllProjects()
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func testArtifactoryTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := artifactoryAuth.NewArtifactoryDetails()
	details.SetUrl(url)
	servicesManager, err := artifactory.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	// Expect timeout
	_, err = servicesManager.GetVersion()
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func testDistributionTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := distributionAuth.NewDistributionDetails()
	details.SetUrl(url)
	servicesManager, err := distribution.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	// Expect timeout
	_, err = servicesManager.GetDistributionStatus(distributionServices.DistributionStatusParams{})
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func testLifecycleTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := lifecycleAuth.NewLifecycleDetails()
	details.SetUrl(url)
	servicesManager, err := lifecycle.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	// Expect timeout
	_, err = servicesManager.GetReleaseBundleCreationStatus(lifecycleServices.ReleaseBundleDetails{}, "", false)
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func testEvidenceTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := evidenceAuth.NewEvidenceDetails()
	details.SetUrl(url)
	servicesManager, err := evidence.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	dsseFile := []byte("dsse file")
	serviceDetails := services.EvidenceDetails{
		SubjectUri:  "repository/path/to/file.txt",
		DSSEFileRaw: dsseFile,
	}

	// Expect timeout
	_, err = servicesManager.UploadEvidence(serviceDetails)
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func testPipelinesTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := pipelinesAuth.NewPipelinesDetails()
	details.SetUrl(url)
	servicesManager, err := pipelines.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	// Expect timeout
	_, err = servicesManager.GetSystemInfo()
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func testXrayTimeout(t *testing.T) {
	// Create mock server
	url, cleanup := createSleepyRequestServer()
	defer cleanup()

	// Create services manager configuring to work with the mock server
	details := xrayAuth.NewXrayDetails()
	details.SetUrl(url)
	servicesManager, err := xray.New(createServiceConfigWithTimeout(t, details))
	assert.NoError(t, err)

	// Expect timeout
	_, err = servicesManager.GetVersion()
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func createServiceConfigWithTimeout(t *testing.T, serverDetails auth.ServiceDetails) config.Config {
	serviceConfig, err := config.NewConfigBuilder().SetOverallRequestTimeout(overallRequestTimeout).SetServiceDetails(serverDetails).Build()
	assert.NoError(t, err)
	return serviceConfig
}

// Create a mock HTTP server that sleeps before responding to requests
func createSleepyRequestServer() (url string, cleanup func()) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(handlerTimeout)
	})
	server := httptest.NewServer(handler)
	url = server.URL + "/"
	cleanup = server.Close
	return
}
