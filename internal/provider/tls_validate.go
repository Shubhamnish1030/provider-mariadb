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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	mariadbv1alpha1 "github.com/mariadb-operator/mariadb-operator/v26/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
	"github.com/openeverest/openeverest/v2/provider-runtime/controller"

	"github.com/openeverest/provider-mariadb/definition"
)

// The values the TLS parameters accept.
var (
	tlsModes    = []definition.TLSMode{definition.TLSModeDisabled, definition.TLSModePrefer, definition.TLSModeRequire}
	issuerKinds = []definition.IssuerKind{definition.IssuerKindIssuer, definition.IssuerKindClusterIssuer}
)

// ownSecretSuffixes name, after the instance, the Secrets the operator, the
// provider and the runtime write for it.
var ownSecretSuffixes = []string{
	serverCertSecretSuffix, "-ca", "-client-cert", tlsCABundleSuffix, "-conn",
}

const (
	tlsOffForbidden    = "TLS cannot be turned off on an existing instance: disabled can only be set when the instance is created"
	tlsSourceForbidden = "certificateSecretName and issuer cannot change while TLS is on: "
)

// validateTLS checks the TLS parameters of in on their own.
func validateTLS(in *corev1alpha1.Instance) field.ErrorList {
	params, err := instanceTLS(in)
	if err != nil {
		return field.ErrorList{field.Invalid(field.NewPath("spec", "parameters"), field.OmitValueType{}, err.Error())}
	}

	var errs field.ErrorList
	if !slices.Contains(tlsModes, params.Mode) {
		errs = append(errs, field.NotSupported(tlsPath.Child("mode"), params.Mode, tlsModes))
	}
	if params.Mode == definition.TLSModeDisabled {
		if params.CertificateSecretName != "" || params.Issuer != nil || len(params.AdditionalNames) > 0 {
			errs = append(errs, field.Forbidden(tlsPath,
				"certificateSecretName, issuer and additionalNames apply only with TLS on: set mode to preferTLS or requireTLS"))
		}
		if params.GaleraSSTEnabled != nil && bool(*params.GaleraSSTEnabled) {
			errs = append(errs, field.Invalid(tlsPath.Child("galeraSSTEnabled"), true, "must be false while TLS is disabled"))
		}
	}

	if name := params.CertificateSecretName; name != "" {
		path := tlsPath.Child("certificateSecretName")
		if msgs := validation.IsDNS1123Subdomain(name); len(msgs) > 0 {
			errs = append(errs, field.Invalid(path, name, strings.Join(msgs, "; ")))
		}
		if slices.Contains(ownSecretNames(in.Name), name) {
			errs = append(errs, field.Invalid(path, name,
				"the name of a Secret created for the instance, which would overwrite yours; name the Secret differently"))
		}
	}

	if issuer := params.Issuer; issuer != nil {
		path := tlsPath.Child("issuer")
		if params.CertificateSecretName != "" {
			errs = append(errs, field.Forbidden(path, "use either certificateSecretName or an issuer, not both"))
		}
		if issuer.Name == "" {
			errs = append(errs, field.Required(path.Child("name"), ""))
		} else if msgs := validation.IsDNS1123Subdomain(issuer.Name); len(msgs) > 0 {
			errs = append(errs, field.Invalid(path.Child("name"), issuer.Name, strings.Join(msgs, "; ")))
		}
		ref := issuerReference(issuer)
		if ref.Group == certManagerGroup && !slices.Contains(issuerKinds, definition.IssuerKind(ref.Kind)) {
			errs = append(errs, field.NotSupported(path.Child("kind"), issuer.Kind, issuerKinds))
		}
	}

	namesPath := tlsPath.Child("additionalNames")
	if len(params.AdditionalNames) > 0 && params.CertificateSecretName != "" {
		errs = append(errs, field.Forbidden(namesPath,
			"cannot be combined with certificateSecretName: the certificate in the Secret carries its own names"))
	}
	for i, name := range params.AdditionalNames {
		if net.ParseIP(name) != nil {
			errs = append(errs, field.Invalid(namesPath.Index(i), name, "must be a DNS name, not an IP address"))
			continue
		}
		if msgs := validation.IsDNS1123Subdomain(strings.TrimPrefix(name, "*.")); len(msgs) > 0 {
			errs = append(errs, field.Invalid(namesPath.Index(i), name, "must be a DNS name: "+strings.Join(msgs, "; ")))
		}
	}
	return errs
}

// ownSecretNames are the Secrets created for the instance name.
func ownSecretNames(name string) []string {
	names := []string{userSecretName(name), rootSecretName(name)}
	for _, suffix := range ownSecretSuffixes {
		names = append(names, name+suffix)
	}
	return names
}

// certificateSource identifies where the certificate of params comes from.
func certificateSource(params definition.TLSParameters) string {
	switch {
	case params.CertificateSecretName != "":
		return "the Secret " + params.CertificateSecretName
	case params.Issuer != nil:
		return describeIssuer(issuerReference(params.Issuer))
	}
	return "the CA created for the instance"
}

func describeIssuer(ref cmmeta.IssuerReference) string {
	return fmt.Sprintf("the %s %s of %s", ref.Kind, ref.Name, ref.Group)
}

// validateTLSTransition rejects, on an update of a provisioned Instance,
// turning TLS off and changing where the certificate comes from.
// validateDeployedTLS checks the same against the running MariaDB.
func validateTLSTransition(in, old *corev1alpha1.Instance) field.ErrorList {
	before, err := instanceTLS(old)
	if err != nil || before.Mode == definition.TLSModeDisabled {
		return nil
	}
	after, err := instanceTLS(in)
	if err != nil {
		return nil
	}
	if after.Mode == definition.TLSModeDisabled {
		return field.ErrorList{field.Forbidden(tlsPath.Child("mode"), tlsOffForbidden)}
	}
	if from, to := certificateSource(before), certificateSource(after); from != to {
		return field.ErrorList{field.Forbidden(tlsPath, tlsSourceForbidden+"the certificate comes from "+from)}
	}
	return nil
}

// validateDeployedTLS is validateTLSTransition against the running MariaDB
// (nil before it exists), whose Instance may be from an earlier release or
// not at hand. It also checks the certificate of certificateSecretName, once
// the Secret exists.
func validateDeployedTLS(c *controller.Context, mdb *mariadbv1alpha1.MariaDB) (field.ErrorList, error) {
	params, err := instanceTLS(c.Instance())
	if err != nil {
		// validateTLS reports it.
		return nil, nil //nolint:nilerr
	}
	var errs field.ErrorList
	if name := params.CertificateSecretName; name != "" && params.Mode != definition.TLSModeDisabled {
		path := tlsPath.Child("certificateSecretName")
		secret := &corev1.Secret{}
		switch err := c.Get(secret, name); {
		case apierrors.IsNotFound(err):
			errs = append(errs, field.NotFound(path, name))
		case err != nil:
			return nil, fmt.Errorf("get the certificate Secret %s: %w", name, err)
		default:
			if err := checkCertificateSecret(secret, requiredTLSNames(c)); err != nil {
				errs = append(errs, field.Invalid(path, name, err.Error()))
			}
		}
	}

	if mdb == nil || !mdb.IsTLSEnabled() {
		return errs, nil
	}
	if params.Mode == definition.TLSModeDisabled {
		return append(errs, field.Forbidden(tlsPath.Child("mode"), tlsOffForbidden)), nil
	}
	if from, to := deployedCertificateSource(mdb), certificateSource(params); from != to {
		errs = append(errs, field.Forbidden(tlsPath, tlsSourceForbidden+"the instance's certificate comes from "+from))
	}
	return errs, nil
}

// deployedCertificateSource is certificateSource of a running MariaDB.
func deployedCertificateSource(mdb *mariadbv1alpha1.MariaDB) string {
	tls := ptr.Deref(mdb.Spec.TLS, mariadbv1alpha1.TLS{})
	switch {
	case tls.ServerCertSecretRef != nil:
		return "the Secret " + tls.ServerCertSecretRef.Name
	case tls.ServerCertIssuerRef != nil:
		ref := *tls.ServerCertIssuerRef
		return describeIssuer(issuerReference(&definition.IssuerReference{
			Name: ref.Name, Kind: definition.IssuerKind(ref.Kind), Group: ref.Group,
		}))
	}
	return "the CA created for the instance"
}

// requiredTLSNames are the names the operator, the replicas and in-cluster
// clients verify the server certificate against: the client Service, on
// galera and replication every pod, and localhost, which the operator's
// probes connect to.
func requiredTLSNames(c *controller.Context) []string {
	service := c.Name()
	if isHATopology(c) {
		service = c.Name() + primaryServiceSuffix
	}
	ns := c.Namespace()
	names := []string{
		fmt.Sprintf("%s.%s.svc.cluster.local", service, ns),
		fmt.Sprintf("%s.%s.svc", service, ns),
	}
	if isHATopology(c) {
		for i := range engineReplicas(c.Instance()) {
			names = append(names, fmt.Sprintf("%s-%d.%s-internal.%s.svc.cluster.local", c.Name(), i, c.Name(), ns))
		}
	}
	return append(names, "localhost")
}

// checkCertificateSecret checks a certificate Secret the user provides: it
// holds a certificate and its key (tls.crt, tls.key) and the CA certificate
// (ca.crt), the CA verifies the certificate, as replicas and clients will,
// and the certificate is valid for names.
func checkCertificateSecret(secret *corev1.Secret, names []string) error {
	var missing []string
	for _, key := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, tlsCAKey} {
		if len(secret.Data[key]) == 0 {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the Secret has no %s", strings.Join(missing, ", "))
	}
	if _, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]); err != nil {
		return fmt.Errorf("tls.crt and tls.key do not hold a certificate and its private key: %w", err)
	}
	chain, err := parseCertificates(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return fmt.Errorf("tls.crt: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(secret.Data[tlsCAKey]) {
		return errors.New("ca.crt holds no PEM certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("the CA of ca.crt does not verify the certificate of tls.crt for server authentication: %w", err)
	}
	var uncovered []string
	for _, name := range names {
		if leaf.VerifyHostname(name) != nil {
			uncovered = append(uncovered, name)
		}
	}
	if len(uncovered) > 0 {
		return fmt.Errorf("the certificate is not valid for %s: the operator, the replicas and in-cluster clients connect by these names",
			strings.Join(uncovered, ", "))
	}
	return nil
}

// parseCertificates decodes the PEM certificates of data, at least one.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate")
	}
	return certs, nil
}
