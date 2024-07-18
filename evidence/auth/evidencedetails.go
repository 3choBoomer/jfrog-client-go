package auth

import (
	"github.com/3choboomer/jfrog-client-go/auth"
)

func NewEvidenceDetails() auth.ServiceDetails {
	return &evidenceDetails{}
}

type evidenceDetails struct {
	auth.CommonConfigFields
}

func (rt *evidenceDetails) GetVersion() (string, error) {
	panic("Failed: Method is not implemented")
}
