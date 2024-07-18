package distribution

import (
	"github.com/3choboomer/jfrog-client-go/config"
	"github.com/3choboomer/jfrog-client-go/distribution/services"
	"github.com/3choboomer/jfrog-client-go/http/jfroghttpclient"
	clientutils "github.com/3choboomer/jfrog-client-go/utils"
	"github.com/3choboomer/jfrog-client-go/utils/distribution"
)

type DistributionServicesManager struct {
	client *jfroghttpclient.JfrogHttpClient
	config config.Config
}

func New(config config.Config) (*DistributionServicesManager, error) {
	details := config.GetServiceDetails()
	var err error
	manager := &DistributionServicesManager{config: config}
	manager.client, err = jfroghttpclient.JfrogClientBuilder().
		SetCertificatesPath(config.GetCertificatesPath()).
		SetInsecureTls(config.IsInsecureTls()).
		SetContext(config.GetContext()).
		SetDialTimeout(config.GetDialTimeout()).
		SetOverallRequestTimeout(config.GetOverallRequestTimeout()).
		SetClientCertPath(details.GetClientCertPath()).
		SetClientCertKeyPath(details.GetClientCertKeyPath()).
		AppendPreRequestInterceptor(details.RunPreRequestFunctions).
		SetContext(config.GetContext()).
		SetRetries(config.GetHttpRetries()).
		SetRetryWaitMilliSecs(config.GetHttpRetryWaitMilliSecs()).
		Build()
	return manager, err
}

func (sm *DistributionServicesManager) SetSigningKey(params services.SetSigningKeyParams) error {
	setSigningKeyService := services.NewSetSigningKeyService(sm.client)
	setSigningKeyService.DistDetails = sm.config.GetServiceDetails()
	return setSigningKeyService.SetSigningKey(params)
}

func (sm *DistributionServicesManager) CreateReleaseBundle(params services.CreateReleaseBundleParams) (*clientutils.Sha256Summary, error) {
	createBundleService := services.NewCreateReleaseBundleService(sm.client)
	createBundleService.DistDetails = sm.config.GetServiceDetails()
	createBundleService.DryRun = sm.config.IsDryRun()
	return createBundleService.CreateReleaseBundle(params)
}

func (sm *DistributionServicesManager) UpdateReleaseBundle(params services.UpdateReleaseBundleParams) (*clientutils.Sha256Summary, error) {
	createBundleService := services.NewUpdateReleaseBundleService(sm.client)
	createBundleService.DistDetails = sm.config.GetServiceDetails()
	createBundleService.DryRun = sm.config.IsDryRun()
	return createBundleService.UpdateReleaseBundle(params)
}

func (sm *DistributionServicesManager) SignReleaseBundle(params services.SignBundleParams) (*clientutils.Sha256Summary, error) {
	signBundleService := services.NewSignBundleService(sm.client)
	signBundleService.DistDetails = sm.config.GetServiceDetails()
	return signBundleService.SignReleaseBundle(params)
}

func (sm *DistributionServicesManager) DistributeReleaseBundle(params distribution.DistributionParams, autoCreateRepo bool) error {
	distributeBundleService := services.NewDistributeReleaseBundleV1Service(sm.client)
	distributeBundleService.DistDetails = sm.config.GetServiceDetails()
	distributeBundleService.DryRun = sm.config.IsDryRun()
	distributeBundleService.AutoCreateRepo = autoCreateRepo
	distributeBundleService.DistributeParams = params
	return distributeBundleService.Distribute()
}

func (sm *DistributionServicesManager) DistributeReleaseBundleSync(params distribution.DistributionParams, maxWaitMinutes int, autoCreateRepo bool) error {
	distributeBundleService := services.NewDistributeReleaseBundleV1Service(sm.client)
	distributeBundleService.DistDetails = sm.config.GetServiceDetails()
	distributeBundleService.DryRun = sm.config.IsDryRun()
	distributeBundleService.MaxWaitMinutes = maxWaitMinutes
	distributeBundleService.Sync = true
	distributeBundleService.AutoCreateRepo = autoCreateRepo
	distributeBundleService.DistributeParams = params
	return distributeBundleService.Distribute()
}

func (sm *DistributionServicesManager) GetDistributionStatus(params services.DistributionStatusParams) (*[]distribution.DistributionStatusResponse, error) {
	distributeBundleService := services.NewDistributionStatusService(sm.client)
	distributeBundleService.DistDetails = sm.config.GetServiceDetails()
	return distributeBundleService.GetStatus(params)
}

func (sm *DistributionServicesManager) DeleteReleaseBundle(params services.DeleteDistributionParams) error {
	deleteBundleService := services.NewDeleteReleaseBundleService(sm.client)
	deleteBundleService.DistDetails = sm.config.GetServiceDetails()
	deleteBundleService.DryRun = sm.config.IsDryRun()
	return deleteBundleService.DeleteDistribution(params)
}

func (sm *DistributionServicesManager) DeleteLocalReleaseBundle(params services.DeleteDistributionParams) error {
	deleteLocalBundleService := services.NewDeleteLocalDistributionService(sm.client)
	deleteLocalBundleService.DistDetails = sm.config.GetServiceDetails()
	deleteLocalBundleService.DryRun = sm.config.IsDryRun()
	return deleteLocalBundleService.DeleteDistribution(params)
}

func (sm *DistributionServicesManager) Client() *jfroghttpclient.JfrogHttpClient {
	return sm.client
}

func (sm *DistributionServicesManager) Config() config.Config {
	return sm.config
}

func (sm *DistributionServicesManager) GetDistributionVersion() (string, error) {
	versionService := services.NewVersionService(sm.client)
	versionService.DistDetails = sm.config.GetServiceDetails()
	return versionService.GetDistributionVersion()
}
