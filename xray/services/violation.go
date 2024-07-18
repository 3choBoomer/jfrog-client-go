package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	artUtils "github.com/3choboomer/jfrog-client-go/artifactory/services/utils"
	"github.com/3choboomer/jfrog-client-go/auth"
	"github.com/3choboomer/jfrog-client-go/http/jfroghttpclient"
	clientUtils "github.com/3choboomer/jfrog-client-go/utils"
	"github.com/3choboomer/jfrog-client-go/utils/errorutils"
	"github.com/3choboomer/jfrog-client-go/utils/io/httputils"
	"github.com/3choboomer/jfrog-client-go/utils/log"
)

const (
	ViolationsUrl                      = "api/v1/violations"
	IgnoredSubPath                     = "ignored"
	minXrayViolationsVersionForList    = "3.11"
	minXrayViolationsVersionForRestore = "3.16"
)

// ViolationsService defines the http client and Xray details
type ViolationsService struct {
	client      *jfroghttpclient.JfrogHttpClient
	XrayDetails auth.ServiceDetails
}

type ViolationNotFoundError struct {
	InnerError error
}

func (e ViolationNotFoundError) Error() string {
	innerErrorText := ""
	if e.InnerError != nil {
		innerErrorText = e.InnerError.Error()
	}
	return fmt.Sprintf("Xray: ignore rule not found. %s", innerErrorText)
}

// NewViolationsService creates a new Xray Policy Service
func NewViolationsService(client *jfroghttpclient.JfrogHttpClient) *ViolationsService {
	return &ViolationsService{client: client}
}

// GetXrayDetails returns the Xray details
func (vs *ViolationsService) GetXrayDetails() auth.ServiceDetails {
	return vs.XrayDetails
}

// GetJfrogHttpClient returns the http client
func (vs *ViolationsService) GetJfrogHttpClient() *jfroghttpclient.JfrogHttpClient {
	return vs.client
}

func (vs *ViolationsService) CheckMinimumVersionForRestore() error {
	return vs.checkMinVersion(minXrayViolationsVersionForRestore)
}

func (vs *ViolationsService) CheckMinimumVersionForList() error {
	return vs.checkMinVersion(minXrayViolationsVersionForList)
}

func (vs *ViolationsService) checkMinVersion(minVersion string) error {
	xrDetails := vs.GetXrayDetails()
	if xrDetails == nil {
		return errorutils.CheckErrorf("Xray details not configured.")
	}
	version, err := xrDetails.GetVersion()
	if err != nil {
		return fmt.Errorf("couldn't get Xray version. Error: %w", err)
	}

	return clientUtils.ValidateMinimumVersion(clientUtils.Xray, version, minVersion)
}

func (vs *ViolationsService) getViolationsURL() string {
	return fmt.Sprintf("%s%s", vs.XrayDetails.GetUrl(), ViolationsUrl)
}

// Restore Restores violations that were ignored by an Ignore Rule by violation ID.
func (vs *ViolationsService) Restore(violationIds ...string) error {
	if err := vs.CheckMinimumVersionForRestore(); err != nil {
		return err
	}
	httpClientsDetails := vs.setupHttpClient()

	request := struct {
		Ids []string `json:"ids,omitempty"`
	}{
		Ids: violationIds,
	}

	content, err := json.Marshal(request)
	if err != nil {
		return errorutils.CheckErrorf("error marshalling request %w", err)
	}

	url := fmt.Sprintf("%s/%s", vs.getViolationsURL(), "restore")
	resp, body, err := vs.client.SendPost(url, content, &httpClientsDetails)
	if err != nil {
		return err
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusNoContent, http.StatusOK); err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			notFound := ViolationNotFoundError{InnerError: err}
			return notFound
		}
		return err
	}
	return nil
}

// Get retrieves the details about Xray Violations based on the filters provided
// Corresponds to the POST /api/v1/violations endpoint
func (vs *ViolationsService) Get(filters *ViolationsGetAllParams) (response *ViolationsResponse, err error) {
	httpClientsDetails := vs.XrayDetails.CreateHttpClientDetails()
	reqBody, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}
	resp, body, err := vs.client.SendPost(vs.getViolationsURL(), reqBody, &httpClientsDetails)
	response = &ViolationsResponse{}
	if err != nil {
		return nil, err
	}
	log.Debug("Xray response:", resp.Status)
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		return nil, errors.New("failed unmarshalling violations response")
	}

	return response, nil
}

// GetIgnoredViolationsByWatchName retrieves the details about all ignored Violations for the given watch name
// Corresponds to the GET /violations/ignored/{watch_name} endpoint
func (vs *ViolationsService) GetIgnoredViolationsByWatchName(watchName string) (ignored *IgnoredViolationsResponse, err error) {
	httpClientsDetails := vs.setupHttpClient()
	url := fmt.Sprintf("%s%s%s",
		clientUtils.AddTrailingSlashIfNeeded(vs.getViolationsURL()),
		clientUtils.AddTrailingSlashIfNeeded(IgnoredSubPath),
		watchName)

	resp, body, _, err := vs.client.SendGet(url, true, &httpClientsDetails)
	ignored = &IgnoredViolationsResponse{}
	if err != nil {
		return nil, err
	}
	log.Debug("Xray response:", resp.Status)
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return nil, err
	}
	log.Info(fmt.Sprintf("%s", string(body)))
	err = json.Unmarshal(body, ignored)
	if err != nil {
		return nil, errors.New("failed unmarshalling Ignored Violations")
	}

	return ignored, nil
}

// GetIgnoredViolations Lists the details about all ignored Violations that match the given filters
// Corresponds to the POST /api/v1/violations/ignored endpoint
func (vs *ViolationsService) GetIgnoredViolations(filters *ListIgnoredViolationsFilters) (ignored *ListIgnoredViolationsResponse, err error) {
	if err = vs.CheckMinimumVersionForList(); err != nil {
		return nil, err
	}
	httpClientsDetails := vs.setupHttpClient()
	url := fmt.Sprintf("%s%s",
		clientUtils.AddTrailingSlashIfNeeded(vs.getViolationsURL()),
		clientUtils.AddTrailingSlashIfNeeded(IgnoredSubPath))

	content, err := json.Marshal(filters)
	if err != nil {
		return nil, errorutils.CheckErrorf("error marshalling filter %w", err)
	}

	resp, body, err := vs.client.SendPost(url, content, &httpClientsDetails)
	ignored = &ListIgnoredViolationsResponse{}
	if err != nil {
		return nil, err
	}
	log.Debug("Xray response:", resp.Status)
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, ignored)
	if err != nil {
		return nil, errors.New("failed unmarshalling Ignored Violations")
	}

	return ignored, nil
}

func (vs *ViolationsService) setupHttpClient() httputils.HttpClientDetails {
	httpClientsDetails := vs.XrayDetails.CreateHttpClientDetails()
	artUtils.SetContentType("application/JSON", &httpClientsDetails.Headers)
	return httpClientsDetails
}

type ViolationsGetAllFilters struct {
	WatchName     string    `json:"watch_name,omitempty"`
	ViolationType string    `json:"violation_type,omitempty"`
	MinSeverity   string    `json:"min_severity,omitempty"`
	CreatedFrom   time.Time `json:"created_from,omitempty"`
	CreatedUntil  time.Time `json:"created_until,omitempty"`
	CveID         string    `json:"cve_id,omitempty"`
	Resources     Resources `json:"resources,omitempty"`
}

type ViolationsGetAllParams struct {
	Filters    ViolationsGetAllFilters `json:"filters"`
	Pagination ViolationPagination     `json:"pagination"`
}

type Build struct {
	Name    string `json:"name,omitempty"`
	Number  string `json:"number,omitempty"`
	Project string `json:"project,omitempty"`
}

type ReleaseBundleV2 struct {
	NameVersion
	Project string `json:"project,omitempty"`
}

type Resources struct {
	Artifacts        []ViolationArtifactDescriptor `json:"artifacts,omitempty"`
	Builds           []Build                       `json:"builds,omitempty"`
	ReleaseBundles   []NameVersion                 `json:"release_bundles,omitempty"`
	ReleaseBundlesV2 []ReleaseBundleV2             `json:"release_bundles_v2,omitempty"`
}

type ViolationArtifactDescriptor struct {
	Repo string `json:"repo,omitempty"`
	Path string `json:"path,omitempty"`
}

type ViolationPagination struct {
	OrderBy   string `json:"order_by,omitempty"`
	Direction string `json:"direction,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

type ViolationDetail struct {
	Description         string              `json:"description,omitempty"`
	Severity            string              `json:"severity,omitempty"`
	Type                string              `json:"type,omitempty"`
	InfectedComponents  []string            `json:"infected_components,omitempty"`
	Created             time.Time           `json:"created,omitempty"`
	WatchName           string              `json:"watch_name,omitempty"`
	IssueID             string              `json:"issue_id,omitempty"`
	ViolationDetailsURL string              `json:"violation_details_url,omitempty"`
	ImpactedArtifacts   []string            `json:"impacted_artifacts,omitempty"`
	ExtendedInformation ExtendedInformation `json:"extended_information,omitempty"`
}

type ViolationsResponse struct {
	TotalViolations int               `json:"total_violations,omitempty"`
	Violations      []ViolationDetail `json:"violations,omitempty"`
}

type IgnoredViolationDetail struct {
	ViolationDetail
	MatchedPolicies     []string            `json:"matched_policies,omitempty"`
	IgnoreRuleInfo      IgnoreRuleDetail    `json:"ignore_rule_info,omitempty"`
	ExtendedInformation ExtendedInformation `json:"extended_information,omitempty"`
}

type IgnoredViolationsResponse struct {
	TotalViolations int               `json:"violations_count,omitempty"`
	Violations      []ViolationDetail `json:"violations,omitempty"`
}

type ListIgnoredViolationsFilters struct {
	Vulnerabilities []string           `json:"vulnerabilities,omitempty"`
	Licenses        []string           `json:"licenses,omitempty"`
	Cves            []string           `json:"cves,omitempty"`
	Policies        []string           `json:"policies,omitempty"`
	Watches         []string           `json:"watches,omitempty"`
	DockerLayers    []string           `json:"docker_layers,omitempty"`
	ReleaseBundles  NameVersion        `json:"release_bundles,omitempty"`
	Builds          NameVersion        `json:"builds,omitempty"`
	Components      NameVersion        `json:"components,omitempty"`
	Artifacts       ArtifactDescriptor `json:"artifacts,omitempty"`
}

type MatchedPolicy struct {
	Policy     string `json:"policy,omitempty"`
	Rule       string `json:"rule,omitempty"`
	IsBlocking bool   `json:"is_blocking,omitempty"`
}

type ListIgnoreViolationsIgnoreRuleDetails struct {
	ID        string    `json:"id,omitempty"`
	Author    string    `json:"author,omitempty"`
	Created   time.Time `json:"created,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	DeletedBy string    `json:"deleted_by,omitempty"`
	DeletedAt time.Time `json:"deleted_at,omitempty"`
}

type Property struct {
	Cve    string   `json:"cve,omitempty"`
	Cwe    []string `json:"cwe,omitempty"`
	CvssV2 string   `json:"cvssv2,omitempty"`
	CvssV3 string   `json:"cvssv3,omitempty"`
}

type ListIgnoreViolationsViolationDescriptor struct {
	ViolationID       string                                `json:"violation_id,omitempty"`
	IssueID           string                                `json:"issue_id,omitempty"`
	Type              string                                `json:"type,omitempty"`
	Created           time.Time                             `json:"created,omitempty"`
	WatchName         string                                `json:"watch_name,omitempty"`
	Provider          string                                `json:"provider,omitempty"`
	Description       string                                `json:"description,omitempty"`
	Severity          string                                `json:"severity,omitempty"`
	ImpactedArtifact  ArtifactDescriptor                    `json:"impacted_artifact,omitempty"`
	MatchedPolicies   []MatchedPolicy                       `json:"matched_policies,omitempty"`
	IgnoreRuleDetails ListIgnoreViolationsIgnoreRuleDetails `json:"ignore_rule_details,omitempty"`
	Properties        []Property                            `json:"properties,omitempty"`
}

type ListIgnoredViolationsResponse struct {
	Data       []ListIgnoreViolationsViolationDescriptor `json:"data,omitempty"`
	TotalCount int                                       `json:"total_count,omitempty"`
}
