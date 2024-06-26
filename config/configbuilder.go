package config

import (
	"context"
	"net/http"
	"time"

	"github.com/3choboomer/jfrog-client-go/auth"
	"github.com/3choboomer/jfrog-client-go/http/httpclient"
)

func NewConfigBuilder() *servicesConfigBuilder {
	configBuilder := &servicesConfigBuilder{}
	configBuilder.threads = 3
	configBuilder.dialTimeout = httpclient.DefaultDialTimeout
	configBuilder.httpRetries = 3
	configBuilder.httpRetryWaitMilliSecs = 0
	return configBuilder
}

type servicesConfigBuilder struct {
	auth.ServiceDetails
	certificatesPath       string
	threads                int
	isDryRun               bool
	insecureTls            bool
	ctx                    context.Context
	dialTimeout            time.Duration
	overallRequestTimeout  time.Duration
	httpRetries            int
	httpRetryWaitMilliSecs int
	httpClient             *http.Client
}

func (builder *servicesConfigBuilder) SetServiceDetails(artDetails auth.ServiceDetails) *servicesConfigBuilder {
	builder.ServiceDetails = artDetails
	return builder
}

func (builder *servicesConfigBuilder) SetCertificatesPath(certificatesPath string) *servicesConfigBuilder {
	builder.certificatesPath = certificatesPath
	return builder
}

func (builder *servicesConfigBuilder) SetThreads(threads int) *servicesConfigBuilder {
	builder.threads = threads
	return builder
}

func (builder *servicesConfigBuilder) SetDryRun(dryRun bool) *servicesConfigBuilder {
	builder.isDryRun = dryRun
	return builder
}

func (builder *servicesConfigBuilder) SetInsecureTls(insecureTls bool) *servicesConfigBuilder {
	builder.insecureTls = insecureTls
	return builder
}

func (builder *servicesConfigBuilder) SetContext(ctx context.Context) *servicesConfigBuilder {
	builder.ctx = ctx
	return builder
}

func (builder *servicesConfigBuilder) SetDialTimeout(dialTimeout time.Duration) *servicesConfigBuilder {
	builder.dialTimeout = dialTimeout
	return builder
}

func (builder *servicesConfigBuilder) SetOverallRequestTimeout(overallRequestTimeout time.Duration) *servicesConfigBuilder {
	builder.overallRequestTimeout = overallRequestTimeout
	return builder
}

func (builder *servicesConfigBuilder) SetHttpRetries(httpRetries int) *servicesConfigBuilder {
	builder.httpRetries = httpRetries
	return builder
}

func (builder *servicesConfigBuilder) SetHttpRetryWaitMilliSecs(httpRetryWaitMilliSecs int) *servicesConfigBuilder {
	builder.httpRetryWaitMilliSecs = httpRetryWaitMilliSecs
	return builder
}

func (builder *servicesConfigBuilder) SetHttpClient(httpClient *http.Client) *servicesConfigBuilder {
	builder.httpClient = httpClient
	return builder
}

func (builder *servicesConfigBuilder) Build() (Config, error) {
	c := &servicesConfig{}
	c.ServiceDetails = builder.ServiceDetails
	c.threads = builder.threads
	c.certificatesPath = builder.certificatesPath
	c.dryRun = builder.isDryRun
	c.insecureTls = builder.insecureTls
	c.ctx = builder.ctx
	c.dialTimeout = builder.dialTimeout
	c.overallRequestTimeout = builder.overallRequestTimeout
	c.httpRetries = builder.httpRetries
	c.httpRetryWaitMilliSecs = builder.httpRetryWaitMilliSecs
	c.httpClient = builder.httpClient
	return c, nil
}
