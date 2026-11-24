// Copyright (C) 2026 The OpenEverest Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"context"
	"fmt"
	"testing"

	mariadbv1alpha1 "github.com/mariadb-operator/mariadb-operator/v26/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	backupv1alpha1 "github.com/openeverest/openeverest/v2/api/backup/v1alpha1"
	commonv1alpha1 "github.com/openeverest/openeverest/v2/api/common/v1alpha1"
	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
	"github.com/openeverest/openeverest/v2/provider-runtime/controller"

	"github.com/openeverest/provider-mariadb/internal/common"
)

const (
	statusTestImage    = "mariadb:12.3"
	statusTestOldImage = "mariadb:11.8"
)

// statusCluster is a database as the operator leaves it: a MariaDB object,
// its StatefulSet and pods, and the Secrets the connection details come from.
type statusCluster struct {
	topology string
	replicas int32
	proxy    bool
	mdb      *mariadbv1alpha1.MariaDB
	sts      *appsv1.StatefulSet
	pods     []*corev1.Pod
	user     *mariadbv1alpha1.User
	grant    *mariadbv1alpha1.Grant
	extra    []client.Object
}

// readyCluster returns a database that runs what the Instance asks for.
func readyCluster(topology string, replicas int32) *statusCluster {
	sc := &statusCluster{topology: topology, replicas: replicas}
	sc.mdb = &mariadbv1alpha1.MariaDB{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Generation: 1},
		Spec: mariadbv1alpha1.MariaDBSpec{
			Replicas:          replicas,
			ContainerTemplate: mariadbv1alpha1.ContainerTemplate{},
		},
		Status: mariadbv1alpha1.MariaDBStatus{
			Conditions:     []metav1.Condition{readyCondition(mariadbv1alpha1.ConditionReasonStatefulSetReady, "Running")},
			CurrentPrimary: ptr.To("test-0"),
		},
	}
	sc.mdb.Spec.Image = statusTestImage
	sc.mdb.Spec.Username = ptr.To(defaultInitialUser)
	sc.mdb.Spec.Database = ptr.To(defaultInitialDatabase)
	sc.mdb.Spec.PasswordSecretKeyRef = &mariadbv1alpha1.GeneratedSecretKeyRef{
		SecretKeySelector: mariadbv1alpha1.SecretKeySelector{
			LocalObjectReference: mariadbv1alpha1.LocalObjectReference{Name: userSecretName("test")},
			Key:                  userPasswordSecretKey,
		},
	}
	sc.user = &mariadbv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: sc.mdb.MariadbUserKey().Name, Namespace: "default"},
		Status:     mariadbv1alpha1.UserStatus{Conditions: []metav1.Condition{readyCondition("Created", "Created")}},
	}
	sc.grant = &mariadbv1alpha1.Grant{
		ObjectMeta: metav1.ObjectMeta{Name: sc.mdb.MariadbGrantKey().Name, Namespace: "default"},
		Status:     mariadbv1alpha1.GrantStatus{Conditions: []metav1.Condition{readyCondition("Created", "Created")}},
	}
	if topology == "galera" {
		sc.mdb.Spec.Galera = &mariadbv1alpha1.Galera{Enabled: true}
	}
	sc.sts = &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Generation: 2},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(replicas),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: mariadbContainerName, Image: statusTestImage}},
			}},
		},
		Status: appsv1.StatefulSetStatus{
			ObservedGeneration: 2,
			Replicas:           replicas,
			UpdatedReplicas:    replicas,
			ReadyReplicas:      replicas,
		},
	}
	for i := range replicas {
		sc.pods = append(sc.pods, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-%d", i),
				Namespace: "default",
				Labels:    mariadbPodLabels("test"),
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: mariadbContainerName, Image: statusTestImage}}},
			Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			}},
		})
	}
	return sc
}

func readyCondition(reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               mariadbv1alpha1.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

func notReadyCondition(reason, message string) metav1.Condition {
	c := readyCondition(reason, message)
	c.Status = metav1.ConditionFalse
	return c
}

func (sc *statusCluster) withProxy(ready bool) *statusCluster {
	sc.proxy = true
	mxs := &mariadbv1alpha1.MaxScale{
		ObjectMeta: metav1.ObjectMeta{Name: maxScaleName("test"), Namespace: "default"},
	}
	readyReplicas := int32(0)
	if ready {
		mxs.Status.Conditions = []metav1.Condition{readyCondition("Running", "Running")}
		readyReplicas = maxScaleDefaultReplicas
	} else {
		mxs.Status.Conditions = []metav1.Condition{notReadyCondition("NotReady", "Not ready")}
	}
	mxs.Spec.Replicas = maxScaleDefaultReplicas
	mxs.Spec.Image = testMaxScaleImage
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: mxs.Name, Namespace: "default", Generation: 1},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(maxScaleDefaultReplicas),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: maxScaleContainerName, Image: testMaxScaleImage}},
			}},
		},
		Status: appsv1.StatefulSetStatus{
			ObservedGeneration: 1,
			Replicas:           maxScaleDefaultReplicas,
			UpdatedReplicas:    maxScaleDefaultReplicas,
			ReadyReplicas:      readyReplicas,
		},
	}
	sc.extra = append(sc.extra, mxs, sts)
	return sc
}

func (sc *statusCluster) context(t *testing.T) *controller.Context {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1alpha1.AddToScheme(scheme))
	require.NoError(t, backupv1alpha1.AddToScheme(scheme))
	require.NoError(t, mariadbv1alpha1.AddToScheme(scheme))

	instance := &corev1alpha1.Instance{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", UID: "uid"},
		Spec: corev1alpha1.InstanceSpec{
			Topology: &corev1alpha1.TopologySpec{Type: sc.topology},
			Components: map[string]corev1alpha1.ComponentSpec{
				common.ComponentEngine: {
					Type:     common.ComponentTypeMariaDB,
					Replicas: ptr.To(sc.replicas),
				},
			},
			Parameters: &runtime.RawExtension{Raw: []byte(`{"tls":{"mode":"disabled"}}`)},
		},
	}
	if sc.proxy {
		instance.Spec.Components[common.ComponentProxy] = corev1alpha1.ComponentSpec{
			Type:       "maxscale",
			Image:      testMaxScaleImage,
			Parameters: &runtime.RawExtension{Raw: []byte(`{"enabled":true}`)},
		}
	}

	objs := append([]client.Object{instance}, connectionSecrets("test")...)
	if sc.mdb != nil {
		objs = append(objs, sc.mdb)
	}
	if sc.sts != nil {
		objs = append(objs, sc.sts)
	}
	for _, p := range sc.pods {
		objs = append(objs, p)
	}
	if sc.user != nil {
		objs = append(objs, sc.user)
	}
	if sc.grant != nil {
		objs = append(objs, sc.grant)
	}
	objs = append(objs, sc.extra...)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithIndex(&backupv1alpha1.Restore{}, controller.IndexRestoreInstanceName, func(o client.Object) []string {
			return []string{o.(*backupv1alpha1.Restore).Spec.InstanceRef.Name}
		}).
		Build()
	return controller.NewContext(context.Background(), cl, instance, common.ProviderName)
}

func (sc *statusCluster) status(t *testing.T) controller.Status {
	t.Helper()
	status, err := StatusMariaDB(sc.context(t))
	require.NoError(t, err)
	return status
}

func operationTypes(status controller.Status) []string {
	var types []string
	for _, op := range status.Operations {
		types = append(types, op.Type)
	}
	return types
}

func desired(status controller.Status) map[string]int32 {
	out := map[string]int32{}
	for _, r := range status.DesiredReplicas {
		out[r.Component] = r.Desired
	}
	return out
}

func TestStatusMariaDB_NotCreated(t *testing.T) {
	sc := readyCluster("galera", 3)
	sc.mdb, sc.sts, sc.pods = nil, nil, nil

	status := sc.status(t)
	assert.False(t, status.Converged)
	assert.Equal(t, "Waiting for the MariaDB object to be created", status.Message)
	assert.Equal(t, map[string]int32{common.ComponentEngine: 3}, desired(status))
	assert.True(t, status.ConnectionDetails.IsEmpty())
}

func TestStatusMariaDB_Ready(t *testing.T) {
	for _, topology := range []string{"standalone", "replication", "galera"} {
		t.Run(topology, func(t *testing.T) {
			replicas := int32(3)
			if topology == "standalone" {
				replicas = 1
			}
			status := readyCluster(topology, replicas).status(t)
			assert.True(t, status.Converged, status.Message)
			assert.Equal(t, controller.Available, status.Available)
			assert.Empty(t, status.Problems)
			assert.Empty(t, status.Operations)
			assert.Equal(t, map[string]int32{common.ComponentEngine: replicas}, desired(status))
			assert.Equal(t, "mysql", status.ConnectionDetails.Type)
		})
	}
}

func TestStatusMariaDB_RollingChangeStaysAvailable(t *testing.T) {
	sc := readyCluster("galera", 3)
	sc.mdb.Status.Conditions = []metav1.Condition{notReadyCondition(mariadbv1alpha1.ConditionReasonUpdating, "Updating")}
	sc.sts.Status.UpdatedReplicas = 1
	sc.pods[2].Status.Conditions[0].Status = corev1.ConditionFalse

	status := sc.status(t)
	assert.False(t, status.Converged)
	assert.Equal(t, "Waiting for MariaDB to be ready (the operator reports: Updating)", status.Message)
	assert.Equal(t, controller.Available, status.Available)
	assert.Empty(t, status.Problems)
	assert.False(t, status.ConnectionDetails.IsEmpty(), "details follow a rollout while clients can connect")
}

func TestStatusMariaDB_StaleOperatorReadiness(t *testing.T) {
	t.Run("resources not applied to the StatefulSet yet", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		sc.mdb.Spec.Resources = &mariadbv1alpha1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
		}
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the operator to apply the latest configuration", status.Message)
		assert.Empty(t, status.Operations)
	})

	t.Run("replicas not applied to the StatefulSet yet", func(t *testing.T) {
		sc := readyCluster("replication", 3)
		sc.mdb.Spec.Replicas = 5
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the operator to scale MariaDB to 5 pods (it runs 3)", status.Message)
	})

	t.Run("pod template not observed yet", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		sc.sts.Status.ObservedGeneration = 1
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for StatefulSet test to pick up its new pod template", status.Message)
	})
}

func TestStatusMariaDB_Upgrading(t *testing.T) {
	sc := readyCluster("galera", 3)
	sc.sts.Spec.Template.Spec.Containers[0].Image = statusTestOldImage
	for _, p := range sc.pods {
		p.Spec.Containers[0].Image = statusTestOldImage
	}

	status := sc.status(t)
	assert.False(t, status.Converged)
	require.Len(t, status.Operations, 1)
	assert.Equal(t, controller.Operation{
		Type:    corev1alpha1.ConditionUpgrading,
		Reason:  reasonRollingOutImage,
		Message: "Rolling out image " + statusTestImage,
	}, status.Operations[0])
}

func TestStatusMariaDB_Availability(t *testing.T) {
	t.Run("primary not ready", func(t *testing.T) {
		sc := readyCluster("replication", 3)
		sc.pods[0].Status.Conditions[0].Status = corev1.ConditionFalse
		sc.sts.Status.ReadyReplicas = 2
		status := sc.status(t)
		assert.Equal(t, controller.Unavailable, status.Available)
		assert.Equal(t, reasonNoPrimary, status.AvailableReason)
		assert.True(t, status.ConnectionDetails.IsEmpty())
	})

	t.Run("replica not ready keeps a replication cluster available", func(t *testing.T) {
		sc := readyCluster("replication", 3)
		sc.pods[1].Status.Conditions[0].Status = corev1.ConditionFalse
		assert.Equal(t, controller.Available, sc.status(t).Available)
	})

	t.Run("primary not reported", func(t *testing.T) {
		sc := readyCluster("replication", 3)
		sc.mdb.Status.CurrentPrimary = nil
		status := sc.status(t)
		assert.Equal(t, controller.AvailabilityUnknown, status.Available)
		assert.Equal(t, reasonPrimaryNotReported, status.AvailableReason)
	})

	t.Run("galera with one synced node", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		sc.pods[0].Status.Conditions[0].Status = corev1.ConditionFalse
		sc.pods[1].Status.Conditions[0].Status = corev1.ConditionFalse
		assert.Equal(t, controller.Available, sc.status(t).Available)
	})

	t.Run("galera with no synced node", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		for _, p := range sc.pods {
			p.Status.Conditions[0].Status = corev1.ConditionFalse
		}
		status := sc.status(t)
		assert.Equal(t, controller.Unavailable, status.Available)
		assert.Equal(t, reasonNoNodeReady, status.AvailableReason)
	})
}

func TestStatusMariaDB_Problems(t *testing.T) {
	tests := []struct {
		name      string
		condition metav1.Condition
		reason    string
	}{
		{"init error", notReadyCondition(mariadbv1alpha1.ConditionReasonInitError, "init failed"), reasonInitializationFailed},
		{"scale out error", notReadyCondition(mariadbv1alpha1.ConditionReasonScaleOutError, "scale out failed"), reasonScaleOutFailed},
		{"replica recovery error", notReadyCondition(mariadbv1alpha1.ConditionReasonReplicaRecoverError, "recovery failed"), reasonReplicaRecoveryFailed},
		{"binlog archiving error", notReadyCondition(mariadbv1alpha1.ConditionReasonArchiveBinlogsError, "archive failed"), reasonBinlogArchivingFailed},
		{"unhealthy pass", notReadyCondition(mariadbv1alpha1.ConditionReasonHealthy, "connection refused"), corev1alpha1.ReasonEngineError},
		{"conflicting write", notReadyCondition(mariadbv1alpha1.ConditionReasonHealthy,
			"Operation cannot be fulfilled on mariadbs.k8s.mariadb.com \"test\": the object has been modified"), ""},
		{"wait", notReadyCondition(mariadbv1alpha1.ConditionReasonInitializing, "Initializing"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := readyCluster("galera", 3)
			sc.mdb.Status.Conditions = []metav1.Condition{tt.condition}
			status := sc.status(t)
			assert.False(t, status.Converged)
			if tt.reason == "" {
				assert.Empty(t, status.Problems)
				return
			}
			require.Len(t, status.Problems, 1)
			assert.Equal(t, controller.Problem{Reason: tt.reason, Message: tt.condition.Message}, status.Problems[0])
			assert.Equal(t, "The operator reports an error: "+tt.condition.Message, status.Message)
		})
	}
}

func TestStatusMariaDB_InitialUser(t *testing.T) {
	t.Run("not created yet", func(t *testing.T) {
		sc := readyCluster("replication", 3)
		sc.user, sc.grant = nil, nil
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the operator to create the initial user", status.Message)
		assert.Equal(t, controller.Unavailable, status.Available)
		assert.Equal(t, reasonInitialUserNotReady, status.AvailableReason)
		assert.True(t, status.ConnectionDetails.IsEmpty(), "credentials that do not work yet are not handed out")
	})

	t.Run("not granted yet", func(t *testing.T) {
		sc := readyCluster("replication", 3)
		sc.grant.Status.Conditions = []metav1.Condition{notReadyCondition("Failed", "Error")}
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the operator to grant the initial user its privileges", status.Message)
		assert.Equal(t, controller.Unavailable, status.Available)
	})
}

func TestStatusMariaDB_SuspendedOutsideOpenEverest(t *testing.T) {
	sc := readyCluster("galera", 3)
	sc.mdb.Spec.Suspend = true

	status := sc.status(t)
	assert.False(t, status.Converged)
	require.Len(t, status.Problems, 1)
	assert.Equal(t, reasonSuspendedOutsideOpenEverest, status.Problems[0].Reason)
	assert.True(t, status.Problems[0].Terminal)
	assert.Equal(t, controller.Available, status.Available, "the pods keep serving")
}

func TestStatusMariaDB_StorageResizing(t *testing.T) {
	sc := readyCluster("galera", 3)
	sc.mdb.Status.Conditions = append(sc.mdb.Status.Conditions, metav1.Condition{
		Type:               mariadbv1alpha1.ConditionTypeStorageResized,
		Status:             metav1.ConditionFalse,
		Reason:             mariadbv1alpha1.ConditionReasonWaitStorageResize,
		LastTransitionTime: metav1.Now(),
	})

	status := sc.status(t)
	assert.False(t, status.Converged)
	require.Len(t, status.Operations, 1)
	assert.Equal(t, corev1alpha1.ConditionStorageResizing, status.Operations[0].Type)
	assert.Equal(t, corev1alpha1.ReasonStorageFileSystemResizePending, status.Operations[0].Reason)
}

func TestStatusMariaDB_Restores(t *testing.T) {
	t.Run("seeding from a data source", func(t *testing.T) {
		c := readyCluster("galera", 3).context(t)
		c.SetDataSourceStatus(controller.DataSourceStatus{State: controller.DataSourceStateRestoring, Message: "Restoring backup-1"})

		status, err := StatusMariaDB(c)
		require.NoError(t, err)
		assert.False(t, status.Converged)
		assert.Equal(t, "Restoring backup-1", status.Message)
		assert.Equal(t, []string{corev1alpha1.ConditionRestoring}, operationTypes(status))
		assert.Equal(t, corev1alpha1.ReasonSeeding, status.Operations[0].Reason)
		assert.Equal(t, controller.Unavailable, status.Available)
		assert.Equal(t, corev1alpha1.ReasonLoadingData, status.AvailableReason)
		assert.True(t, status.ConnectionDetails.IsEmpty(), "an empty database is not handed out")
	})

	t.Run("failed seeding leaves the failure to DataSourceReady", func(t *testing.T) {
		c := readyCluster("galera", 3).context(t)
		c.SetDataSourceStatus(controller.DataSourceStatus{Done: true, State: controller.DataSourceStateFailed})

		status, err := StatusMariaDB(c)
		require.NoError(t, err)
		assert.Empty(t, status.Operations)
	})

	t.Run("operator errors while data loads are not problems", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		sc.mdb.Status.Conditions = []metav1.Condition{notReadyCondition(mariadbv1alpha1.ConditionReasonHealthy, "connection refused")}
		c := sc.context(t)
		c.SetDataSourceStatus(controller.DataSourceStatus{State: controller.DataSourceStateRestoring})

		status, err := StatusMariaDB(c)
		require.NoError(t, err)
		assert.Empty(t, status.Problems)
	})

	t.Run("in-place restore", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		sc.extra = append(sc.extra,
			&backupv1alpha1.Restore{
				ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"},
				Spec:       backupv1alpha1.RestoreSpec{InstanceRef: commonv1alpha1.ObjectRef{Name: "test"}},
				Status:     backupv1alpha1.RestoreStatus{State: backupv1alpha1.RestoreStateRunning},
			},
			&backupv1alpha1.Restore{
				ObjectMeta: metav1.ObjectMeta{Name: "r0", Namespace: "default"},
				Spec:       backupv1alpha1.RestoreSpec{InstanceRef: commonv1alpha1.ObjectRef{Name: "test"}},
				Status:     backupv1alpha1.RestoreStatus{State: backupv1alpha1.RestoreStateSucceeded},
			},
		)
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Restore r1 is running", status.Message)
		assert.Equal(t, []string{corev1alpha1.ConditionRestoring}, operationTypes(status))
		assert.Equal(t, reasonRestoring, status.AvailableReason)
	})
}

func TestStatusMariaDB_Proxy(t *testing.T) {
	t.Run("not created", func(t *testing.T) {
		sc := readyCluster("galera", 3)
		sc.proxy = true
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the MaxScale proxy to be created", status.Message)
		assert.Equal(t, controller.Unavailable, status.Available)
		assert.Equal(t, reasonNoProxyReady, status.AvailableReason)
		assert.Equal(t, map[string]int32{common.ComponentEngine: 3, common.ComponentProxy: maxScaleDefaultReplicas}, desired(status))
	})

	t.Run("not ready", func(t *testing.T) {
		status := readyCluster("galera", 3).withProxy(false).status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the MaxScale proxy to be ready (the operator reports: Not ready)", status.Message)
		assert.Equal(t, controller.Unavailable, status.Available)
	})

	t.Run("scale not applied to the StatefulSet yet", func(t *testing.T) {
		sc := readyCluster("galera", 3).withProxy(true)
		sc.extra[0].(*mariadbv1alpha1.MaxScale).Spec.Replicas = 3
		status := sc.status(t)
		assert.False(t, status.Converged)
		assert.Equal(t, "Waiting for the operator to scale MaxScale to 3 pods (it runs 2)", status.Message)
		assert.Equal(t, controller.Available, status.Available)
	})

	t.Run("ready", func(t *testing.T) {
		status := readyCluster("galera", 3).withProxy(true).status(t)
		assert.True(t, status.Converged, status.Message)
		assert.Equal(t, controller.Available, status.Available)
		assert.Equal(t, "test-maxscale.default.svc", status.ConnectionDetails.Host)
	})
}

func TestEnqueueStatefulSetInstance(t *testing.T) {
	owned := func(kind, name string) *appsv1.StatefulSet {
		return &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: mariadbv1alpha1.GroupVersion.String(),
				Kind:       kind,
				Name:       name,
				Controller: ptr.To(true),
			}},
		}}
	}
	enqueue := enqueueOperatorChildInstance()
	want := []types.NamespacedName{{Namespace: "ns", Name: "db"}}
	for _, obj := range []*appsv1.StatefulSet{owned("MariaDB", "db"), owned("MaxScale", "db-maxscale")} {
		var got []types.NamespacedName
		for _, r := range enqueue(context.Background(), obj) {
			got = append(got, r.NamespacedName)
		}
		assert.Equal(t, want, got, obj.Name)
	}
	assert.Empty(t, enqueue(context.Background(), &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "other"}}))
}
