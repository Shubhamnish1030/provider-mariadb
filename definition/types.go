// Package definition contains shared types used across the provider definition.
//
// +k8s:openapi-gen=true
package definition

import "github.com/openeverest/provider-mariadb/definition/components"

// TopologyType represents a supported MariaDB deployment topology.
type TopologyType string

const (
	// TopologyTypeStandalone is a single MariaDB node (no HA).
	TopologyTypeStandalone TopologyType = "standalone"
	// TopologyTypeGalera is a multi-master Galera cluster (production HA).
	// Added in Phase 3.
	TopologyTypeGalera TopologyType = "galera"
	// TopologyTypeReplication is async primary/replica replication.
	// Added in Phase 4 (operator marks this feature alpha).
	TopologyTypeReplication TopologyType = "replication"
)

// Parameters defines instance-wide structured parameters that apply to the
// entire cluster (Instance.spec.parameters).
type Parameters struct {
	// TLS configures encryption in transit: between clients and MariaDB,
	// between the replicas, and between Galera nodes.
	// +optional
	TLS *TLSParameters `json:"tls,omitempty"`
}

// TLSMode controls whether TLS is on and which client connections must use it.
// +enum
type TLSMode string

const (
	// TLSModeDisabled turns TLS off. Can only be set when the instance is
	// created.
	TLSModeDisabled TLSMode = "disabled"
	// TLSModePrefer serves TLS and accepts clients with or without it. The
	// default.
	TLSModePrefer TLSMode = "preferTLS"
	// TLSModeRequire rejects clients that do not use TLS
	// (require_secure_transport), at MariaDB and at the MaxScale proxy.
	TLSModeRequire TLSMode = "requireTLS"
)

// TLSParameters configures TLS for the instance. The server certificate comes
// from, in order of precedence: certificateSecretName, the cert-manager
// issuer, or else a CA the mariadb-operator creates for the instance. The
// certificate source is chosen when TLS is turned on and cannot change while
// it is on. The mariadb-operator restarts the pods, one at a time, whenever
// the server certificate changes.
type TLSParameters struct {
	// Mode is disabled, preferTLS or requireTLS. Changing it restarts the
	// pods, one at a time. TLS cannot be turned off on an existing instance.
	// +default="preferTLS"
	// +optional
	Mode TLSMode `json:"mode,omitempty"`

	// CertificateSecretName names a Secret in the instance namespace with the
	// server certificate, followed by any intermediate CA certificates
	// (tls.crt), its private key (tls.key) and the CA certificate it is
	// verified with (ca.crt). The certificate must be valid for the names of
	// the instance's Services and, for galera and replication, of its pods
	// (*.<instance>-internal.<namespace>.svc.cluster.local), for localhost,
	// which the operator's probes connect to, and for the names clients
	// connect to. Does not need cert-manager. Cannot be
	// combined with issuer or additionalNames.
	// +optional
	CertificateSecretName string `json:"certificateSecretName,omitempty"`

	// Issuer is the cert-manager issuer that signs the server certificate,
	// instead of the CA the mariadb-operator creates. The operator requests
	// it as the Certificate <instance>-server-cert and cert-manager renews
	// it. The issuer must write its CA certificate to ca.crt, as the CA and
	// Vault issuers do.
	// +optional
	Issuer *IssuerReference `json:"issuer,omitempty"`

	// AdditionalNames are DNS names the server certificate is valid for
	// besides those of the instance's Services and pods, such as an external
	// name clients connect to. Used with issuer or the operator's CA; cannot
	// be combined with certificateSecretName, whose certificate carries its
	// own names. Changing them on a running instance reissues the
	// certificate and restarts the pods, so it waits for maintenance
	// approval.
	// +optional
	AdditionalNames []string `json:"additionalNames,omitempty"`

	// GaleraSSTEnabled encrypts Galera state snapshot transfers. Defaults to
	// true on the galera topology; ignored on the others.
	// +optional
	GaleraSSTEnabled *components.FlexBool `json:"galeraSSTEnabled,omitempty"`
}

// IssuerKind is the kind of a cert-manager issuer.
// +enum
type IssuerKind string

const (
	// IssuerKindIssuer is an Issuer in the instance namespace.
	IssuerKindIssuer IssuerKind = "Issuer"
	// IssuerKindClusterIssuer is a cluster-wide ClusterIssuer.
	IssuerKindClusterIssuer IssuerKind = "ClusterIssuer"
)

// IssuerReference refers to a cert-manager issuer.
type IssuerReference struct {
	// Name of the issuer.
	Name string `json:"name"`

	// Kind of the issuer: Issuer or ClusterIssuer, or the kind of an
	// external issuer of group.
	// +default="Issuer"
	// +optional
	Kind IssuerKind `json:"kind,omitempty"`

	// Group is the API group of an external issuer, such as
	// awspca.cert-manager.io.
	// +default="cert-manager.io"
	// +optional
	Group string `json:"group,omitempty"`
}
