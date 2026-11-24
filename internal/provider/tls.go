// Copyright (C) 2026 The OpenEverest Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	mariadbv1alpha1 "github.com/mariadb-operator/mariadb-operator/v26/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
	"github.com/openeverest/openeverest/v2/provider-runtime/controller"

	"github.com/openeverest/provider-mariadb/definition"
)

const (
	tlsCAKey          = "ca.crt"
	tlsConnectionKey  = "tls"
	tlsCABundleSuffix = "-ca-bundle"

	certManagerGroup = "cert-manager.io"
	// serverCertSecretSuffix names, after the MariaDB, the Secret the
	// operator writes the server certificate it issues to.
	serverCertSecretSuffix = "-server-cert"
	// tlsNamesTokenPrefix prefixes the maintenance token of an additionalNames
	// change; the rest is a hash of the names.
	tlsNamesTokenPrefix = "tls-names-"
)

var tlsPath = field.NewPath("spec", "parameters", "tls")

type tlsSettings struct {
	Enabled          bool
	Required         bool
	GaleraSSTEnabled bool
}

// instanceTLS decodes spec.parameters.tls with the default mode applied.
// Unknown fields are rejected: the schema only rejects them at the top level,
// and a mistyped or pre-migration field such as tls.required must not be
// silently dropped.
func instanceTLS(in *corev1alpha1.Instance) (definition.TLSParameters, error) {
	var params definition.Parameters
	if in.Spec.Parameters != nil && len(in.Spec.Parameters.Raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(in.Spec.Parameters.Raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&params); err != nil {
			return definition.TLSParameters{}, fmt.Errorf("decode parameters: %w", err)
		}
	}
	tls := ptr.Deref(params.TLS, definition.TLSParameters{})
	if tls.Mode == "" {
		tls.Mode = definition.TLSModePrefer
	}
	return tls, nil
}

// resolveTLSSettings turns the TLS mode into the operator's switches. Galera
// SSTs are encrypted by default whenever TLS is on; galeraSSTEnabled has no
// effect off the galera topology.
func resolveTLSSettings(in *corev1alpha1.Instance) (tlsSettings, error) {
	tls, err := instanceTLS(in)
	if err != nil {
		return tlsSettings{}, err
	}
	settings := tlsSettings{
		Enabled:  tls.Mode != definition.TLSModeDisabled,
		Required: tls.Mode == definition.TLSModeRequire,
	}
	if in.GetTopologyType() == string(definition.TopologyTypeGalera) {
		settings.GaleraSSTEnabled = settings.Enabled
		if tls.GaleraSSTEnabled != nil {
			settings.GaleraSSTEnabled = bool(*tls.GaleraSSTEnabled)
		}
	}
	return settings, nil
}

// buildTLS maps spec.parameters.tls onto the MariaDB's spec.tls. The user's
// certificate Secret is both the server certificate and the CA the operator
// trusts and publishes (its ca.crt), so the operator never needs its key.
// Without one, the operator issues the certificate itself or through the
// cert-manager issuer. Client certificates stay with the operator's CA.
func buildTLS(c *controller.Context) (*mariadbv1alpha1.TLS, error) {
	settings, err := resolveTLSSettings(c.Instance())
	if err != nil {
		return nil, err
	}
	params, err := instanceTLS(c.Instance())
	if err != nil {
		return nil, err
	}

	tls := &mariadbv1alpha1.TLS{
		Enabled:  settings.Enabled,
		Required: ptr.To(settings.Required),
	}
	if isGaleraTopology(c) {
		tls.GaleraSSTEnabled = ptr.To(settings.GaleraSSTEnabled)
	}
	if !settings.Enabled {
		return tls, nil
	}
	switch {
	case params.CertificateSecretName != "":
		ref := &mariadbv1alpha1.LocalObjectReference{Name: params.CertificateSecretName}
		tls.ServerCertSecretRef = ref
		tls.ServerCASecretRef = ref.DeepCopy()
	case params.Issuer != nil:
		tls.ServerCertIssuerRef = ptr.To(issuerReference(params.Issuer))
	}
	tls.ServerCertAdditionalNames = slices.Clone(params.AdditionalNames)
	return tls, nil
}

// issuerReference is issuer with the defaults of its kind and group.
func issuerReference(issuer *definition.IssuerReference) cmmeta.IssuerReference {
	return cmmeta.IssuerReference{
		Name:  issuer.Name,
		Kind:  string(cmp.Or(issuer.Kind, definition.IssuerKindIssuer)),
		Group: cmp.Or(issuer.Group, certManagerGroup),
	}
}

// approveAdditionalNames keeps the additional names the running MariaDB's
// certificate carries until a change is approved: the operator restarts the
// pods when the certificate is reissued for new names. A MariaDB that is
// created or gets TLS now is restarted (or started) anyway, so its names
// apply without approval.
func approveAdditionalNames(c *controller.Context, existing, desired *mariadbv1alpha1.MariaDB) {
	if desired.Spec.TLS == nil || !desired.Spec.TLS.Enabled || !existing.IsTLSEnabled() {
		return
	}
	current := existing.Spec.TLS.ServerCertAdditionalNames
	wanted := desired.Spec.TLS.ServerCertAdditionalNames
	if slices.Equal(current, wanted) {
		return
	}
	description := "Reissue the server certificate without additional names (rolling restart)"
	if len(wanted) > 0 {
		description = fmt.Sprintf("Reissue the server certificate for the additional names %s (rolling restart)",
			strings.Join(wanted, ", "))
	}
	if !c.RequestMaintenance(additionalNamesToken(wanted), description, controller.MaintenanceRollingRestart) {
		desired.Spec.TLS.ServerCertAdditionalNames = slices.Clone(current)
	}
}

// additionalNamesToken identifies a change to names by the names it leads to.
func additionalNamesToken(names []string) string {
	sum := sha256.Sum256([]byte(strings.Join(names, ",")))
	return tlsNamesTokenPrefix + hex.EncodeToString(sum[:])[:10]
}

// reissueServerCertificate makes the operator issue its server certificate
// again when it lacks an additional name the MariaDB declares. The operator
// only checks the certificate's common name and expiry, so it would otherwise
// keep serving the old names until the certificate is renewed. Deleting the
// Secret makes it issue a new one, from the same CA, and restart the pods.
// Certificates from cert-manager or the user's Secret are left alone, as is
// a Secret not controlled by the MariaDB with uid (empty before it exists).
func reissueServerCertificate(c *controller.Context, mdb *mariadbv1alpha1.MariaDB, uid types.UID) error {
	tls := ptr.Deref(mdb.Spec.TLS, mariadbv1alpha1.TLS{})
	if uid == "" || !tls.Enabled || tls.ServerCertSecretRef != nil || tls.ServerCertIssuerRef != nil ||
		len(tls.ServerCertAdditionalNames) == 0 {
		return nil
	}
	secret := &corev1.Secret{}
	if err := c.Get(secret, mdb.Name+serverCertSecretSuffix); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get the server certificate Secret: %w", err)
	}
	if owner := metav1.GetControllerOf(secret); owner == nil || owner.UID != uid {
		return nil
	}
	chain, err := parseCertificates(secret.Data[corev1.TLSCertKey])
	if err != nil {
		// Not ours to repair: the operator replaces an invalid certificate.
		return nil
	}
	missing := slices.DeleteFunc(slices.Clone(tls.ServerCertAdditionalNames), func(name string) bool {
		return slices.ContainsFunc(chain[0].DNSNames, func(dns string) bool { return strings.EqualFold(dns, name) })
	})
	if len(missing) == 0 {
		return nil
	}
	log.FromContext(c.Context()).Info("Reissuing the server certificate for its additional names",
		"secret", secret.Name, "missing", missing)
	if err := c.Delete(secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete the server certificate Secret %s to reissue it: %w", secret.Name, err)
	}
	return nil
}

func tlsCABundleSecretName(instanceName string) string {
	return instanceName + tlsCABundleSuffix
}
