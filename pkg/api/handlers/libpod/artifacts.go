package libpod

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/containers/image/v5/types"
	"github.com/containers/podman/v5/libpod"
	"github.com/containers/podman/v5/pkg/api/handlers/utils"

	domain_utils "github.com/containers/podman/v5/pkg/domain/utils"

	api "github.com/containers/podman/v5/pkg/api/types"
	"github.com/containers/podman/v5/pkg/auth"
	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/containers/podman/v5/pkg/domain/infra/abi"
	"github.com/gorilla/schema"
)

func InspectArtifact(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	name := utils.GetName(r)
	imageEngine := abi.ImageEngine{Libpod: runtime}
	report, err := imageEngine.ArtifactInspect(r.Context(), name, entities.ArtifactInspectOptions{})
	if err != nil {
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusOK, report)
}

func ListArtifact(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	imageEngine := abi.ImageEngine{Libpod: runtime}
	artifacts, err := imageEngine.ArtifactList(r.Context(), entities.ArtifactListOptions{}) // TODO: Why do we need opts here?
	if err != nil {
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusOK, artifacts)
}

func PullArtifact(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	decoder := r.Context().Value(api.DecoderKey).(*schema.Decoder)
	query := struct {
		Name       string `schema:"name"` // NOTE: I think Brent mentioned we want to be strict with this also should it be "reference"
		Quiet      bool   `schema:"quiet"`
		Retry      uint   `schema:"retry"`
		RetryDelay string `schema:"retrydelay"`
		TLSVerify  bool   `schema:"tlsVerify"`
	}{
		TLSVerify: true,
	}

	if err := decoder.Decode(&query, r.URL.Query()); err != nil {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("failed to parse parameters for %s: %w", r.URL.String(), err))
		return
	}

	if len(query.Name) == 0 {
		utils.InternalServerError(w, errors.New("name parameter cannot be empty"))
		return
	}

	artifactsPullOptions := entities.ArtifactPullOptions{}

	if _, found := r.URL.Query()["tlsVerify"]; found {
		artifactsPullOptions.InsecureSkipTLSVerify = types.NewOptionalBool(!query.TLSVerify)
	}

	if _, found := r.URL.Query()["retry"]; found {
		artifactsPullOptions.MaxRetries = &query.Retry
	}

	if len(query.RetryDelay) != 0 {
		artifactsPullOptions.RetryDelay = query.RetryDelay
	}

	authConf, authfile, err := auth.GetCredentials(r)
	if err != nil {
		utils.Error(w, http.StatusBadRequest, err)
		return
	}
	defer auth.RemoveAuthfile(authfile)

	artifactsPullOptions.AuthFilePath = authfile
	if authConf != nil {
		artifactsPullOptions.Username = authConf.Username
		artifactsPullOptions.Password = authConf.Password
		artifactsPullOptions.IdentityToken = authConf.IdentityToken
	}

	imageEngine := abi.ImageEngine{Libpod: runtime}
	artifacts, err := imageEngine.ArtifactPull(r.Context(), query.Name, entities.ArtifactPullOptions{})
	if err != nil {
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusOK, artifacts)
}

func RemoveArtifact(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	imageEngine := abi.ImageEngine{Libpod: runtime}
	name := utils.GetName(r)
	artifacts, err := imageEngine.ArtifactRm(r.Context(), name, entities.ArtifactRemoveOptions{})
	if err != nil {
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusOK, artifacts)
}

func AddArtifact(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	decoder := r.Context().Value(api.DecoderKey).(*schema.Decoder)
	query := struct {
		Name        string   `schema:"name, required"`
		Files       []string `schema:"files, required"`
		Annotations []string `schema:"annotations"`
		Type        string   `schema:"type"`
		Append      bool     `schema:"append"`
	}{
		Append: false,
	}

	if err := decoder.Decode(&query, r.URL.Query()); err != nil {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("failed to parse parameters for %s: %w", r.URL.String(), err))
		return
	}

	if query.Name == "" || len(query.Files) == 0 {
		utils.Error(w, http.StatusBadRequest, errors.New("name and files parameters are required"))
		return
	}

	annotations, err := domain_utils.ParseAnnotations(query.Annotations)
	if err != nil {
		utils.Error(w, http.StatusBadRequest, errors.New("error parsing annotations"))
		return
	}

	artifactAddOptions := &entities.ArtifactAddOptions{
		Append:       query.Append,
		Annotations:  annotations,
		ArtifactType: query.Type,
	}

	imageEngine := abi.ImageEngine{Libpod: runtime}
	artifacts, err := imageEngine.ArtifactAdd(r.Context(), query.Name, query.Files, artifactAddOptions)
	if err != nil {
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusOK, artifacts)
}

func PushArtifact(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value(api.RuntimeKey).(*libpod.Runtime)
	decoder := r.Context().Value(api.DecoderKey).(*schema.Decoder)
	query := struct {
		Quiet      bool   `schema:"quiet"`
		Retry      uint   `schema:"retry"`
		RetryDelay string `schema:"retrydelay"`
		TLSVerify  bool   `schema:"tlsVerify"`
	}{
		TLSVerify: true,
	}

	if err := decoder.Decode(&query, r.URL.Query()); err != nil {
		utils.Error(w, http.StatusBadRequest, fmt.Errorf("failed to parse parameters for %s: %w", r.URL.String(), err))
		return
	}

	name := utils.GetName(r)
	artifactsPushOptions := entities.ArtifactPushOptions{}

	if _, found := r.URL.Query()["tlsVerify"]; found {
		artifactsPushOptions.SkipTLSVerify = types.NewOptionalBool(!query.TLSVerify)
	}

	if _, found := r.URL.Query()["retry"]; found {
		artifactsPushOptions.Retry = &query.Retry
	}

	if len(query.RetryDelay) != 0 {
		artifactsPushOptions.RetryDelay = query.RetryDelay
	}

	authConf, authfile, err := auth.GetCredentials(r)
	if err != nil {
		utils.Error(w, http.StatusBadRequest, err)
		return
	}
	defer auth.RemoveAuthfile(authfile)

	if authConf != nil {
		artifactsPushOptions.Username = authConf.Username
		artifactsPushOptions.Password = authConf.Password
	}

	imageEngine := abi.ImageEngine{Libpod: runtime}
	artifacts, err := imageEngine.ArtifactPush(r.Context(), name, artifactsPushOptions)
	if err != nil {
		utils.InternalServerError(w, err)
		return
	}
	utils.WriteResponse(w, http.StatusOK, artifacts)
}
