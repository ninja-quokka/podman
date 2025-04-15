package server

import (
	"net/http"

	"github.com/containers/podman/v5/pkg/api/handlers/libpod"
	"github.com/gorilla/mux"
)

func (s *APIServer) registerArtifactHandlers(r *mux.Router) error {
	// swagger:operation GET /libpod/artifacts/{name}/json ArtifactName
	// ---
	// summary: Inspect an artifact
	// description: Obtain low-level information about an artifact
	// tags:
	//   - artifacts
	// produces:
	//   - application/json
	// parameters:
	//   - in: path
	//     name: name
	//     type: string
	//     description: artifact name or id
	//     required: true
	// responses:
	//   200:
	//     description: no error
	//     schema:
	//      type: string
	//      format: binary
	//   404:
	//     $ref: "#/responses/artifactNotFound" TODO: This returns a 500
	//   500:
	//     $ref: "#/responses/internalError"
	r.HandleFunc(VersionedPath("/libpod/artifacts/{name}/json"), s.APIHandler(libpod.InspectArtifact)).Methods(http.MethodGet)
	// swagger:operation GET /libpod/artifacts/json ArtifactsList
	// ---
	// tags:
	//  - artifacts
	// summary: List artifacts
	// description: Returns a list of artifacts on the server.
	// parameters:
	// produces:
	// - application/json
	// responses:
	//   200:
	//     $ref: "#/responses/imageList"
	//   500:
	//     $ref: '#/responses/internalError'
	r.HandleFunc(VersionedPath("/libpod/artifacts/json"), s.APIHandler(libpod.ListArtifact)).Methods(http.MethodGet)
	// swagger:operation POST /libpod/artifacts/pull ArtifactsPull
	// ---
	// tags:
	//  - artifacts
	// summary: Pull an OCI artifact
	// description: Pulls an artifact from a registry and stores it locally.
	// parameters:
	//   - in: query
	//     name: name
	//     description: "Mandatory reference to the artifact (e.g., quay.io/image/artifact:tag)"
	//     type: string
	//   - in: query
	//     name: quiet
	//     description: "Silences extra stream data on pull"
	//     type: boolean
	//     default: false
	//   - in: query
	//     name: retry
	//     description: "Number of times to retry in case of failure when performing pull"
	//     type: integer
	//     default: 3
	//   - in: query
	//     name: retryDelay
	//     description: "Delay between retries in case of pull failures (e.g., 10s)"
	//     type: string
	//     default: 1s
	//   - in: query
	//     name: tlsVerify
	//     description: Require TLS verification.
	//     type: boolean
	//     default: true
	//   - in: header
	//     name: X-Registry-Auth
	//     description: "base-64 encoded auth config. Must include the following four values: username, password, email and server address OR simply just an identity token."
	//     type: string
	// produces:
	// - application/json
	// responses:
	//   200:
	//     $ref: "#/responses/imagesPullResponseLibpod"
	//   400:
	//     $ref: "#/responses/badParamError"
	//   500:
	//     $ref: '#/responses/internalError'
	r.Handle(VersionedPath("/libpod/artifacts/pull"), s.APIHandler(libpod.PullArtifact)).Methods(http.MethodPost)
	// swagger:operation DELETE /libpod/artifacts/{name}
	// ---
	// tags:
	//  - artifacts
	// summary: Remove Artifact
	// description: Delete an Artifact from local storage
	// parameters:
	//  - in: path
	//    name: name
	//    type: string
	//    required: true
	//    description: name or ID of artifact to delete
	// produces:
	//  - application/json
	// responses:
	//   200:
	//     $ref: "#/responses/imageDeleteResponse"
	//   500:
	//     $ref: '#/responses/internalError'
	r.Handle(VersionedPath("/libpod/artifacts/{name}"), s.APIHandler(libpod.RemoveArtifact)).Methods(http.MethodDelete)
	// swagger:operation POST /libpod/artifacts/add ArtifactsAdd
	// ---
	// tags:
	//  - artifacts
	// summary: Add an OCI artifact to the local store
	// description: Add an OCI artifact to the local store from the local filesystem
	// parameters:
	//   - in: query
	//     name: name
	//     description: Mandatory reference to the artifact (e.g., quay.io/image/artifact:tag)
	//     type: string
	//   - in: query
	//     name: files
	//     description: Files to be added to the artifact
	//     type: array
	//     items:
	//       type: string
	//   - in: query
	//     name: annotations
	//     description: JSON encoded value of annotations (a map[string]string)
	//     type: string
	//   - in: query
	//     name: type
	//     description: Use type to describe an artifact
	//     type: string
	//   - in: query
	//     name: append
	//     description: Append files to an existing artifact
	//     type: boolean
	//     default: false
	// produces:
	// - application/json
	// responses:
	r.Handle(VersionedPath("/libpod/artifacts/add"), s.APIHandler(libpod.AddArtifact)).Methods(http.MethodPost)

	return nil
}
