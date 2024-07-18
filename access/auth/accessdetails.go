package auth

import (
	"github.com/3choboomer/jfrog-client-go/auth"
)

func NewAccessDetails() auth.ServiceDetails {
	return &accessDetails{}
}

type accessDetails struct {
	auth.CommonConfigFields
}

func (rt *accessDetails) GetVersion() (string, error) {
	panic("Failed: Method is not implemented")
}
