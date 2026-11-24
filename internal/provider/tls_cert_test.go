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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	mariadbv1alpha1 "github.com/mariadb-operator/mariadb-operator/v26/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"

	"github.com/openeverest/provider-mariadb/internal/common"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a server certificate for names and its key, in PEM.
func (ca testCA) issue(t *testing.T, usage x509.ExtKeyUsage, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func certSecret(name string, crt, key, ca []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data:       map[string][]byte{corev1.TLSCertKey: crt, corev1.TLSPrivateKeyKey: key, cmmeta.TLSCAKey: ca},
	}
}

// standaloneNames are the names the standalone instance "test" in "default"
// must be valid for.
var standaloneNames = []string{"test.default.svc.cluster.local", "test.default.svc", "localhost"}

func TestCheckCertificateSecret(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	crt, key := ca.issue(t, x509.ExtKeyUsageServerAuth, standaloneNames...)
	clientCrt, clientKey := ca.issue(t, x509.ExtKeyUsageClientAuth, standaloneNames...)
	_, otherKey := ca.issue(t, x509.ExtKeyUsageServerAuth, standaloneNames...)
	partial, partialKey := ca.issue(t, x509.ExtKeyUsageServerAuth, "test.default.svc")

	tests := []struct {
		name   string
		secret *corev1.Secret
		want   string
	}{
		{name: "valid", secret: certSecret("s", crt, key, ca.pem)},
		{name: "missing keys", secret: certSecret("s", crt, nil, nil), want: "no tls.key, ca.crt"},
		{name: "mismatched key", secret: certSecret("s", crt, otherKey, ca.pem), want: "private key"},
		{name: "other CA", secret: certSecret("s", crt, key, other.pem), want: "does not verify"},
		{name: "client certificate", secret: certSecret("s", clientCrt, clientKey, ca.pem), want: "server authentication"},
		{name: "missing name", secret: certSecret("s", partial, partialKey, ca.pem), want: "not valid for test.default.svc.cluster.local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCertificateSecret(tt.secret, standaloneNames)
			if tt.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	wildcard, wildcardKey := ca.issue(t, x509.ExtKeyUsageServerAuth,
		"test-primary.default.svc.cluster.local", "test-primary.default.svc", "*.test-internal.default.svc.cluster.local")
	assert.NoError(t, checkCertificateSecret(certSecret("s", wildcard, wildcardKey, ca.pem), []string{
		"test-primary.default.svc.cluster.local", "test-0.test-internal.default.svc.cluster.local",
	}), "a wildcard covers the pod names")
}

func TestRequiredTLSNames(t *testing.T) {
	assert.Equal(t, standaloneNames, requiredTLSNames(newTLSContext(t, "", "")))

	c := newTLSContext(t, "replication", "")
	engine := c.Instance().Spec.Components[common.ComponentEngine]
	engine.Replicas = ptr.To(int32(2))
	c.Instance().Spec.Components[common.ComponentEngine] = engine
	assert.Equal(t, []string{
		"test-primary.default.svc.cluster.local", "test-primary.default.svc",
		"test-0.test-internal.default.svc.cluster.local", "test-1.test-internal.default.svc.cluster.local",
		"localhost",
	}, requiredTLSNames(c))
}

func TestBuildTLS(t *testing.T) {
	tests := []struct {
		name     string
		topology string
		params   string
		want     *mariadbv1alpha1.TLS
	}{
		{
			name: "operator CA by default",
			want: &mariadbv1alpha1.TLS{Enabled: true, Required: ptr.To(false)},
		},
		{
			name:     "disabled",
			topology: "galera",
			params:   `{"tls":{"mode":"disabled"}}`,
			want:     &mariadbv1alpha1.TLS{Required: ptr.To(false), GaleraSSTEnabled: ptr.To(false)},
		},
		{
			name:   "certificate Secret is the server certificate and its CA",
			params: `{"tls":{"mode":"requireTLS","certificateSecretName":"db-tls"}}`,
			want: &mariadbv1alpha1.TLS{
				Enabled: true, Required: ptr.To(true),
				ServerCertSecretRef: &mariadbv1alpha1.LocalObjectReference{Name: "db-tls"},
				ServerCASecretRef:   &mariadbv1alpha1.LocalObjectReference{Name: "db-tls"},
			},
		},
		{
			name:     "issuer with defaults and additional names",
			topology: "galera",
			params:   `{"tls":{"issuer":{"name":"ca"},"additionalNames":["db.example.com"],"galeraSSTEnabled":false}}`,
			want: &mariadbv1alpha1.TLS{
				Enabled: true, Required: ptr.To(false), GaleraSSTEnabled: ptr.To(false),
				ServerCertIssuerRef:       &cmmeta.IssuerReference{Name: "ca", Kind: "Issuer", Group: "cert-manager.io"},
				ServerCertAdditionalNames: []string{"db.example.com"},
			},
		},
		{
			name:   "external issuer",
			params: `{"tls":{"issuer":{"name":"pca","kind":"AWSPCAClusterIssuer","group":"awspca.cert-manager.io"}}}`,
			want: &mariadbv1alpha1.TLS{
				Enabled: true, Required: ptr.To(false),
				ServerCertIssuerRef: &cmmeta.IssuerReference{Name: "pca", Kind: "AWSPCAClusterIssuer", Group: "awspca.cert-manager.io"},
			},
		},
		{
			name:   "operator CA with additional names",
			params: `{"tls":{"additionalNames":["db.example.com"]}}`,
			want: &mariadbv1alpha1.TLS{
				Enabled: true, Required: ptr.To(false), ServerCertAdditionalNames: []string{"db.example.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTLS(newTLSContext(t, tt.topology, tt.params))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func mariaDBWithTLS(tls *mariadbv1alpha1.TLS) *mariadbv1alpha1.MariaDB {
	return &mariadbv1alpha1.MariaDB{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", UID: "mdb-uid"},
		Spec:       mariadbv1alpha1.MariaDBSpec{TLS: tls},
	}
}

func TestApproveAdditionalNames(t *testing.T) {
	names := []string{"db.example.com"}
	tests := []struct {
		name        string
		existing    *mariadbv1alpha1.TLS
		approved    func(token string) *corev1alpha1.MaintenanceSpec
		wantNames   []string
		wantPending bool
	}{
		{
			name:      "TLS turned on applies the names",
			existing:  &mariadbv1alpha1.TLS{},
			wantNames: names,
		},
		{
			name:      "unchanged names",
			existing:  &mariadbv1alpha1.TLS{Enabled: true, ServerCertAdditionalNames: names},
			wantNames: names,
		},
		{
			name:        "new names wait for approval",
			existing:    &mariadbv1alpha1.TLS{Enabled: true, ServerCertAdditionalNames: []string{"old.example.com"}},
			wantNames:   []string{"old.example.com"},
			wantPending: true,
		},
		{
			name:     "approved names",
			existing: &mariadbv1alpha1.TLS{Enabled: true},
			approved: func(token string) *corev1alpha1.MaintenanceSpec {
				return &corev1alpha1.MaintenanceSpec{Approved: token}
			},
			wantNames: names,
		},
		{
			name:     "rolling restarts approved up front",
			existing: &mariadbv1alpha1.TLS{Enabled: true},
			approved: func(string) *corev1alpha1.MaintenanceSpec {
				return &corev1alpha1.MaintenanceSpec{AutoApproveUpTo: corev1alpha1.MaintenanceRollingRestart}
			},
			wantNames: names,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTLSContext(t, "", "")
			if tt.approved != nil {
				c.Instance().Spec.Maintenance = tt.approved(additionalNamesToken(names))
			}
			desired := mariaDBWithTLS(&mariadbv1alpha1.TLS{Enabled: true, ServerCertAdditionalNames: names})
			approveAdditionalNames(c, mariaDBWithTLS(tt.existing), desired)

			assert.Equal(t, tt.wantNames, desired.Spec.TLS.ServerCertAdditionalNames)
			pending := c.GetPendingMaintenance()
			if !tt.wantPending {
				assert.Empty(t, pending)
				return
			}
			require.Len(t, pending, 1)
			assert.Equal(t, additionalNamesToken(names), pending[0].ApprovalToken)
			assert.Equal(t, corev1alpha1.MaintenanceRollingRestart, pending[0].Severity)
		})
	}
	assert.NotEqual(t, additionalNamesToken(names), additionalNamesToken(nil), "removing the names is a change of its own")
}

func TestReissueServerCertificate(t *testing.T) {
	ca := newTestCA(t)
	withoutName, key := ca.issue(t, x509.ExtKeyUsageServerAuth, "test.default.svc")
	withName, _ := ca.issue(t, x509.ExtKeyUsageServerAuth, "test.default.svc", "DB.example.com")
	managedTLS := &mariadbv1alpha1.TLS{Enabled: true, ServerCertAdditionalNames: []string{"db.example.com"}}
	owned := func(crt []byte, owner string) *corev1.Secret {
		s := certSecret("test-server-cert", crt, key, ca.pem)
		s.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "k8s.mariadb.com/v1alpha1", Kind: "MariaDB", Name: "test",
			UID: "mdb-uid", Controller: ptr.To(owner == "controller"),
		}}
		return s
	}

	tests := []struct {
		name        string
		tls         *mariadbv1alpha1.TLS
		secret      *corev1.Secret
		wantDeleted bool
	}{
		{name: "certificate lacks a name", tls: managedTLS, secret: owned(withoutName, "controller"), wantDeleted: true},
		{name: "certificate has the names", tls: managedTLS, secret: owned(withName, "controller")},
		{name: "not controlled by the MariaDB", tls: managedTLS, secret: owned(withoutName, "")},
		{
			name: "issued by cert-manager",
			tls: &mariadbv1alpha1.TLS{
				Enabled: true, ServerCertAdditionalNames: []string{"db.example.com"},
				ServerCertIssuerRef: &cmmeta.IssuerReference{Name: "ca"},
			},
			secret: owned(withoutName, "controller"),
		},
		{name: "no additional names", tls: &mariadbv1alpha1.TLS{Enabled: true}, secret: owned(withoutName, "controller")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTLSContext(t, "", "", tt.secret)
			require.NoError(t, reissueServerCertificate(c, mariaDBWithTLS(tt.tls), "mdb-uid"))

			err := c.Get(&corev1.Secret{}, "test-server-cert")
			if tt.wantDeleted {
				assert.True(t, apierrors.IsNotFound(err), "expected the Secret deleted, got %v", err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("no Secret yet", func(t *testing.T) {
		assert.NoError(t, reissueServerCertificate(newTLSContext(t, "", ""), mariaDBWithTLS(managedTLS), "mdb-uid"))
	})
}

func TestValidateDeployedTLS(t *testing.T) {
	ca := newTestCA(t)
	crt, key := ca.issue(t, x509.ExtKeyUsageServerAuth, standaloneNames...)
	ownSecret := certSecret("db-tls", crt, key, ca.pem)
	issuer := &cmmeta.IssuerReference{Name: "ca", Kind: "Issuer", Group: "cert-manager.io"}

	tests := []struct {
		name     string
		params   string
		deployed *mariadbv1alpha1.TLS
		objs     []client.Object
		want     []string
	}{
		{name: "new instance", params: `{"tls":{"issuer":{"name":"ca"}}}`},
		{name: "TLS turned on", params: `{"tls":{"issuer":{"name":"ca"}}}`, deployed: &mariadbv1alpha1.TLS{}},
		{
			name: "TLS turned off", params: `{"tls":{"mode":"disabled"}}`,
			deployed: &mariadbv1alpha1.TLS{Enabled: true},
			want:     []string{"spec.parameters.tls.mode: Forbidden"},
		},
		{
			name: "same issuer", params: `{"tls":{"issuer":{"name":"ca"}}}`,
			deployed: &mariadbv1alpha1.TLS{Enabled: true, ServerCertIssuerRef: issuer},
		},
		{
			name: "issuer added", params: `{"tls":{"issuer":{"name":"ca"}}}`,
			deployed: &mariadbv1alpha1.TLS{Enabled: true},
			want:     []string{"spec.parameters.tls: Forbidden"},
		},
		{
			name: "issuer removed", params: `{"tls":{"mode":"requireTLS"}}`,
			deployed: &mariadbv1alpha1.TLS{Enabled: true, ServerCertIssuerRef: issuer},
			want:     []string{"spec.parameters.tls: Forbidden"},
		},
		{
			name: "valid certificate Secret", params: `{"tls":{"certificateSecretName":"db-tls"}}`,
			deployed: &mariadbv1alpha1.TLS{Enabled: true, ServerCertSecretRef: &mariadbv1alpha1.LocalObjectReference{Name: "db-tls"}},
			objs:     []client.Object{ownSecret},
		},
		{
			name: "missing certificate Secret", params: `{"tls":{"certificateSecretName":"db-tls"}}`,
			want: []string{"spec.parameters.tls.certificateSecretName: Not found"},
		},
		{
			name:   "certificate Secret not valid for the pods",
			params: `{"tls":{"certificateSecretName":"db-tls"}}`,
			objs:   []client.Object{ownSecret},
			want:   []string{"spec.parameters.tls.certificateSecretName: Invalid value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topology := ""
			if strings.Contains(tt.name, "pods") {
				topology = "replication"
			}
			c := newTLSContext(t, topology, tt.params, tt.objs...)
			var mdb *mariadbv1alpha1.MariaDB
			if tt.deployed != nil {
				mdb = mariaDBWithTLS(tt.deployed)
			}
			errs, err := validateDeployedTLS(c, mdb)
			require.NoError(t, err)
			var got []string
			for _, e := range errs {
				got = append(got, strings.SplitN(e.Error(), ":", 3)[0]+":"+strings.SplitN(e.Error(), ":", 3)[1])
			}
			assert.Equal(t, tt.want, got, "errors: %v", errs)
		})
	}
}
