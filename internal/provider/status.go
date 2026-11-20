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
	"errors"
	"fmt"
	"slices"
	"strings"

	mariadbv1alpha1 "github.com/mariadb-operator/mariadb-operator/v26/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	backupv1alpha1 "github.com/openeverest/openeverest/v2/api/backup/v1alpha1"
	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
	"github.com/openeverest/openeverest/v2/provider-runtime/controller"

	"github.com/openeverest/provider-mariadb/internal/common"
)

// Reasons of the problems the provider reports. A problem's reason becomes
// the status word users read, so each names one cause.
const (
	// reasonSuspendedOutsideOpenEverest: spec.suspend is set on the MariaDB
	// object. An Instance cannot ask for that, so it was set there by hand.
	reasonSuspendedOutsideOpenEverest = "SuspendedOutsideOpenEverest"
	reasonInitializationFailed        = "InitializationFailed"
	reasonScaleOutFailed              = "ScaleOutFailed"
	reasonReplicaRecoveryFailed       = "ReplicaRecoveryFailed"
	reasonBinlogArchivingFailed       = "BinlogArchivingFailed"
	reasonBinlogReplayFailed          = "BinlogReplayFailed"
)

// Reasons explaining why clients cannot connect, or why that is unknown.
const (
	reasonNotCreated           = corev1alpha1.ReasonNotCreated
	reasonRestoring            = corev1alpha1.ConditionRestoring
	reasonRotatingRootPassword = "RotatingRootPassword"
	reasonNoPrimary            = "NoPrimary"
	reasonPrimaryNotReported   = "PrimaryNotReported"
	reasonNoNodeReady          = "NoNodeReady"
	reasonNoProxyReady         = "NoProxyReady"
	reasonInitialUserNotReady  = "InitialUserNotReady"
)

// reasonRollingOutImage is the reason of the Upgrading operation.
const reasonRollingOutImage = "RollingOutImage"

// operatorErrorReasons names the problem reported for each reason of the
// operator's Ready condition that is a failure, not a wait.
var operatorErrorReasons = map[string]string{
	mariadbv1alpha1.ConditionReasonInitError:           reasonInitializationFailed,
	mariadbv1alpha1.ConditionReasonScaleOutError:       reasonScaleOutFailed,
	mariadbv1alpha1.ConditionReasonReplicaRecoverError: reasonReplicaRecoveryFailed,
	mariadbv1alpha1.ConditionReasonArchiveBinlogsError: reasonBinlogArchivingFailed,
	mariadbv1alpha1.ConditionReasonReplayBinlogsError:  reasonBinlogReplayFailed,
	mariadbv1alpha1.ConditionReasonFailed:              corev1alpha1.ReasonEngineError,
	// The operator reports an unhealthy pass as Ready=False with this reason
	// and the error as its message.
	mariadbv1alpha1.ConditionReasonHealthy: corev1alpha1.ReasonEngineError,
}

// errFragmentConflict is how the API server refuses a write made from a stale
// read. The operator fails its pass on one and retries at once, so it is no
// failure.
const errFragmentConflict = "Operation cannot be fulfilled"

// restoreInProgress describes a restore that owns the database for now.
type restoreInProgress struct {
	// reason and message go on the Instance's Restoring condition.
	reason, message string
	// seeding is true for the restore that fills a new Instance from its
	// data source.
	seeding bool
	// loadingData is true once data is being loaded. It is false while a new
	// Instance still waits for its database to come up before the restore
	// can start.
	loadingData bool
}

// observation is what the provider reads about the database.
type observation struct {
	mdb *mariadbv1alpha1.MariaDB
	// sts is nil until the operator creates the StatefulSet.
	sts  *appsv1.StatefulSet
	pods []corev1.Pod
	// proxy is nil when the Instance has no MaxScale proxy.
	proxy   *proxyObservation
	restore *restoreInProgress
	// rotatingRoot is true while the root password copied from a snapshot's
	// source is being replaced.
	rotatingRoot bool
	// userWait says what the initial user, whose credentials are the
	// connection details, still waits for, or "" once it can log in.
	userWait string
}

// proxyObservation is what the provider reads about the MaxScale proxy.
type proxyObservation struct {
	// mxs is nil until the MaxScale object exists.
	mxs *mariadbv1alpha1.MaxScale
	// sts is nil until the operator creates the MaxScale StatefulSet.
	sts *appsv1.StatefulSet
}

// StatusMariaDB reports what the provider observes about the database:
// whether it runs what the Instance asks for, whether clients can connect,
// what is wrong and which long operation is running, and how many pods each
// component will have. The runtime derives the Instance's phase and
// conditions from these facts.
func StatusMariaDB(c *controller.Context) (controller.Status, error) {
	obs, err := observe(c)
	if apierrors.IsNotFound(err) {
		return withDesiredReplicas(c, controller.Progressing("Waiting for the MariaDB object to be created")), nil
	}
	if err != nil {
		return controller.Status{}, err
	}

	status := withDesiredReplicas(c, obs.facts())

	// The connection details are reported as soon as clients can connect,
	// not only once the database has converged: whoever is told the database
	// is available must find where to connect, and the details must follow a
	// change that is still rolling out.
	if !status.Converged && status.Available != controller.Available {
		return status, nil
	}

	var mxs *mariadbv1alpha1.MaxScale
	if obs.proxy != nil {
		mxs = obs.proxy.mxs
	}
	details, err := buildConnectionDetails(c, mxs)
	switch {
	case errors.Is(err, errTLSCABundleNotReady):
		return notConverged(status, "Waiting for the MariaDB TLS CA bundle"), nil
	case apierrors.IsNotFound(err):
		// The operator writes the credentials Secrets, so their absence is
		// expected to pass.
		return notConverged(status, "Waiting for the MariaDB credentials Secrets"), nil
	case err != nil:
		return controller.Status{}, fmt.Errorf("build connection details: %w", err)
	}
	status.ConnectionDetails = details
	return status, nil
}

// notConverged keeps the database from reading as converged while the
// provider waits for what message says.
func notConverged(status controller.Status, message string) controller.Status {
	if status.Converged {
		status.Converged = false
		status.Message = message
	}
	return status
}

// observe reads the MariaDB object, its StatefulSet and pods, the MaxScale
// proxy if the Instance has one, and the restore in progress, if any. It
// returns a NotFound error while the MariaDB object does not exist.
func observe(c *controller.Context) (*observation, error) {
	mdb, err := uncachedMariaDB(c)
	if err != nil {
		return nil, err
	}
	obs := &observation{mdb: mdb}

	if obs.restore, err = runningRestore(c); err != nil {
		return nil, err
	}
	if obs.rotatingRoot, err = rootRotationPending(c, mdb); err != nil {
		return nil, err
	}
	if obs.sts, err = statefulSet(c, mdb.Name); err != nil {
		return nil, err
	}
	if obs.pods, err = mariadbPods(c); err != nil {
		return nil, err
	}
	if obs.userWait, err = initialUserWait(c, mdb); err != nil {
		return nil, err
	}

	proxyEnabled, err := isProxyEnabled(c.Instance())
	if err != nil {
		return nil, err
	}
	if proxyEnabled {
		obs.proxy = &proxyObservation{}
		mxs := &mariadbv1alpha1.MaxScale{}
		switch err := c.Get(mxs, maxScaleName(c.Name())); {
		case apierrors.IsNotFound(err):
		case err != nil:
			return nil, fmt.Errorf("get MaxScale: %w", err)
		default:
			obs.proxy.mxs = mxs
			if obs.proxy.sts, err = statefulSet(c, mxs.Name); err != nil {
				return nil, err
			}
		}
	}
	return obs, nil
}

// uncachedMariaDB reads the MariaDB object from the API server instead of the
// cache. Sync has just applied it, and the cache may still hold the object
// from before that, whose spec the checks against the StatefulSet would then
// find already rolled out. The client reads unstructured objects without the
// cache.
func uncachedMariaDB(c *controller.Context) (*mariadbv1alpha1.MariaDB, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(mariadbv1alpha1.GroupVersion.WithKind("MariaDB"))
	if err := c.Get(obj, c.Name()); err != nil {
		return nil, fmt.Errorf("get MariaDB %q: %w", c.Name(), err)
	}
	mdb := &mariadbv1alpha1.MariaDB{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, mdb); err != nil {
		return nil, fmt.Errorf("decode MariaDB %q: %w", c.Name(), err)
	}
	return mdb, nil
}

// initialUserWait says what keeps the initial user from logging in, or ""
// when nothing does. The operator creates it, and its grant, through User and
// Grant objects only once the MariaDB is ready, so the database serves
// clients a moment before the published credentials work.
func initialUserWait(c *controller.Context, mdb *mariadbv1alpha1.MariaDB) (string, error) {
	if !mdb.IsInitialUserEnabled() {
		return "", nil
	}
	user := &mariadbv1alpha1.User{}
	switch err := c.Get(user, mdb.MariadbUserKey().Name); {
	case apierrors.IsNotFound(err):
		return "Waiting for the operator to create the initial user", nil
	case err != nil:
		return "", fmt.Errorf("get User: %w", err)
	case !user.IsReady():
		return "Waiting for the operator to create the initial user", nil
	}
	grant := &mariadbv1alpha1.Grant{}
	switch err := c.Get(grant, mdb.MariadbGrantKey().Name); {
	case apierrors.IsNotFound(err):
		return "Waiting for the operator to grant the initial user its privileges", nil
	case err != nil:
		return "", fmt.Errorf("get Grant: %w", err)
	case !grant.IsReady():
		return "Waiting for the operator to grant the initial user its privileges", nil
	}
	return "", nil
}

// statefulSet returns the named StatefulSet, or nil when it does not exist.
func statefulSet(c *controller.Context, name string) (*appsv1.StatefulSet, error) {
	sts := &appsv1.StatefulSet{}
	if err := c.Get(sts, name); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get StatefulSet %q: %w", name, err)
	}
	return sts, nil
}

// runningRestore returns the restore that is in progress for the Instance, or
// nil. A restore drives the engine through intermediate and momentarily ready
// states, so the Restore object reaching a terminal state is what ends it,
// not what the engine reports meanwhile.
func runningRestore(c *controller.Context) (*restoreInProgress, error) {
	if ds := c.GetDataSourceStatus(); ds != nil && !ds.Done {
		message := ds.Message
		if message == "" {
			message = "The instance is being seeded from its data source"
		}
		return &restoreInProgress{
			reason:      corev1alpha1.ReasonSeeding,
			message:     message,
			seeding:     true,
			loadingData: ds.State == controller.DataSourceStateRestoring,
		}, nil
	}

	name, err := activeRestoreName(c)
	if err != nil || name == "" {
		return nil, err
	}
	return &restoreInProgress{
		reason:      corev1alpha1.ConditionRestoring,
		message:     fmt.Sprintf("Restore %s is running", name),
		loadingData: true,
	}, nil
}

// activeRestoreName returns the name of a Restore targeting the Instance that
// has not reached a terminal state, or "" when there is none.
func activeRestoreName(c *controller.Context) (string, error) {
	restores := &backupv1alpha1.RestoreList{}
	if err := c.List(restores, client.MatchingFields{controller.IndexRestoreInstanceName: c.Name()}); err != nil {
		return "", fmt.Errorf("list Restore resources for instance %q: %w", c.Name(), err)
	}

	var names []string
	for i := range restores.Items {
		r := &restores.Items[i]
		if !r.DeletionTimestamp.IsZero() {
			continue
		}
		switch r.Status.State {
		case backupv1alpha1.RestoreStateSucceeded, backupv1alpha1.RestoreStateFailed:
		default:
			names = append(names, r.Name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	return slices.Min(names), nil
}

// facts turns the observation into the facts the provider reports.
func (o *observation) facts() controller.Status {
	var status controller.Status
	status.Available, status.AvailableReason, status.AvailableMessage = o.availability()

	if o.mdb.IsSuspended() {
		// The provider never sets spec.suspend and does not own the field,
		// so its Sync leaves it alone: only whoever set it can have the
		// operator apply changes again.
		status = status.WithTerminalProblem(reasonSuspendedOutsideOpenEverest,
			"The operator does not apply changes to the database: spec.suspend is set on its MariaDB object, outside OpenEverest. Unset it to resume.")
	}

	// While data is loaded the operator may report errors that come with the
	// restore; one that outlives it is reported once the restore has ended.
	if reason, message, failing := o.operatorError(); failing && (o.restore == nil || !o.restore.loadingData) {
		// Never terminal, even for an error only a person can fix: the
		// operator does not say which generation its error is about, so
		// right after a fix is applied the error still showing may be the
		// one being fixed, and the Instance must not read as stalled then.
		status = status.WithProblem(reason, message)
	}

	if o.restore != nil {
		status = status.WithOperation(corev1alpha1.ConditionRestoring, o.restore.reason, o.restore.message)
	}
	if o.mdb.IsResizingStorage() {
		reason, message := corev1alpha1.ReasonStorageExpansionTriggered, "The data volumes are being resized"
		if o.mdb.IsWaitingForStorageResize() {
			reason, message = corev1alpha1.ReasonStorageFileSystemResizePending, "Waiting for the file systems of the data volumes to be resized"
		}
		status = status.WithOperation(corev1alpha1.ConditionStorageResizing, reason, message)
	}

	status.Message = o.waitingFor()
	status.Converged = status.Message == ""

	if !status.Converged && o.rollingOutImage() {
		status = status.WithOperation(corev1alpha1.ConditionUpgrading, reasonRollingOutImage,
			"Rolling out image "+o.mdb.Spec.Image)
	}
	return status
}

// withDesiredReplicas reports how many pods each component will have once the
// database runs what the Instance asks for. The counts come from the
// Instance, with the defaults Sync applies, not from the MariaDB object,
// which may still describe an earlier spec.
func withDesiredReplicas(c *controller.Context, status controller.Status) controller.Status {
	in := c.Instance()
	status = status.WithDesiredReplicas(common.ComponentEngine, engineReplicas(in))
	if enabled, err := isProxyEnabled(in); err == nil && enabled {
		status = status.WithDesiredReplicas(common.ComponentProxy, maxScaleReplicas(in))
	}
	return status
}

// operatorError returns the problem the operator reports on its Ready
// condition, and whether it reports one.
func (o *observation) operatorError() (reason, message string, failing bool) {
	cond := meta.FindStatusCondition(o.mdb.Status.Conditions, mariadbv1alpha1.ConditionTypeReady)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		return "", "", false
	}
	reason, known := operatorErrorReasons[cond.Reason]
	if !known || strings.Contains(cond.Message, errFragmentConflict) {
		return "", "", false
	}
	message = cond.Message
	if message == "" {
		message = "The operator reports an error without a message"
	}
	return reason, message, true
}

// waitingFor says what keeps the database from running what the Instance
// asks for, in the operator's own words where it has any. It returns "" when
// nothing does.
func (o *observation) waitingFor() string {
	mdb := o.mdb
	switch {
	case mdb.IsSuspended():
		return "The MariaDB object is suspended, so the operator does not apply changes to it"
	case o.restore != nil:
		return o.restore.message
	case o.rotatingRoot:
		return rootRotationMessage
	case o.sts == nil:
		return "Waiting for the operator to create the MariaDB StatefulSet"
	}

	if !mdb.IsReady() {
		if _, message, failing := o.operatorError(); failing {
			return "The operator reports an error: " + message
		}
		if cond := meta.FindStatusCondition(mdb.Status.Conditions, mariadbv1alpha1.ConditionTypeReady); cond != nil && cond.Message != "" {
			return fmt.Sprintf("Waiting for MariaDB to be ready (the operator reports: %s)", cond.Message)
		}
		return "Waiting for the operator to report MariaDB ready"
	}
	if o.userWait != "" {
		return o.userWait
	}
	if mdb.HasPendingUpdate() {
		return "Waiting for the operator to update the pods"
	}
	if mdb.IsResizingStorage() {
		return "Waiting for the data volumes to be resized"
	}

	// The operator does not record which generation of the MariaDB object
	// its Ready condition is about, so the StatefulSet tells whether it has
	// seen the latest spec: it reports ready for the previous one until it
	// changes the StatefulSet.
	if wait := statefulSetBehind(mdb, o.sts); wait != "" {
		return wait
	}
	if wait := rolloutWait(o.sts); wait != "" {
		return "Waiting for " + wait
	}

	if p := o.proxy; p != nil {
		switch {
		case p.mxs == nil:
			return "Waiting for the MaxScale proxy to be created"
		case !p.mxs.IsReady():
			if cond := meta.FindStatusCondition(p.mxs.Status.Conditions, mariadbv1alpha1.ConditionTypeReady); cond != nil && cond.Message != "" {
				return fmt.Sprintf("Waiting for the MaxScale proxy to be ready (the operator reports: %s)", cond.Message)
			}
			return "Waiting for the MaxScale proxy to be ready"
		case p.sts == nil:
			return "Waiting for the operator to create the MaxScale StatefulSet"
		}
		if wait := maxScaleStatefulSetBehind(p.mxs, p.sts); wait != "" {
			return wait
		}
		if wait := rolloutWait(p.sts); wait != "" {
			return "Waiting for " + wait
		}
	}
	return ""
}

// statefulSetBehind says what the operator has yet to apply to the MariaDB
// StatefulSet, from the fields it copies there unchanged, or "" when the
// StatefulSet matches them.
func statefulSetBehind(mdb *mariadbv1alpha1.MariaDB, sts *appsv1.StatefulSet) string {
	if replicas := ptrInt32(sts.Spec.Replicas, 1); replicas != mdb.Spec.Replicas {
		return fmt.Sprintf("Waiting for the operator to scale MariaDB to %d pods (it runs %d)", mdb.Spec.Replicas, replicas)
	}
	container := findContainer(sts.Spec.Template.Spec.Containers, mariadbContainerName)
	if container == nil {
		return ""
	}
	var resources corev1.ResourceRequirements
	if mdb.Spec.Resources != nil {
		resources = mdb.Spec.Resources.ToKubernetesType()
	}
	if container.Image != mdb.Spec.Image || !equality.Semantic.DeepEqual(container.Resources, resources) {
		return "Waiting for the operator to apply the latest configuration"
	}
	return ""
}

// maxScaleStatefulSetBehind says what the operator has yet to apply to the
// MaxScale StatefulSet, from its replica count and image, or "" when the
// StatefulSet matches them.
func maxScaleStatefulSetBehind(mxs *mariadbv1alpha1.MaxScale, sts *appsv1.StatefulSet) string {
	if replicas := ptrInt32(sts.Spec.Replicas, 1); replicas != mxs.Spec.Replicas {
		return fmt.Sprintf("Waiting for the operator to scale MaxScale to %d pods (it runs %d)", mxs.Spec.Replicas, replicas)
	}
	if c := findContainer(sts.Spec.Template.Spec.Containers, maxScaleContainerName); c != nil && c.Image != mxs.Spec.Image {
		return "Waiting for the operator to apply the latest MaxScale configuration"
	}
	return ""
}

// rolloutWait returns what a StatefulSet that has not finished rolling out is
// waiting for, or "" when it has.
//
// The operator replaces pods itself, so its StatefulSets use the OnDelete
// strategy. Their currentRevision then never moves, and a rollout is complete
// when the controller has seen the latest pod template and every pod runs it.
func rolloutWait(sts *appsv1.StatefulSet) string {
	if sts == nil || !sts.DeletionTimestamp.IsZero() {
		return ""
	}
	want := ptrInt32(sts.Spec.Replicas, 1)
	st := sts.Status
	switch {
	case st.ObservedGeneration < sts.Generation:
		return fmt.Sprintf("StatefulSet %s to pick up its new pod template", sts.Name)
	case st.Replicas != want:
		return fmt.Sprintf("StatefulSet %s to scale to %d pods (it has %d)", sts.Name, want, st.Replicas)
	case st.UpdatedReplicas < st.Replicas:
		return fmt.Sprintf("StatefulSet %s to roll out (%d of %d pods updated)", sts.Name, st.UpdatedReplicas, st.Replicas)
	case st.ReadyReplicas < st.Replicas:
		return fmt.Sprintf("StatefulSet %s to become ready (%d of %d pods ready)", sts.Name, st.ReadyReplicas, st.Replicas)
	}
	return ""
}

// rollingOutImage reports whether a MariaDB pod runs an image other than the
// one the MariaDB object asks for, which is how an engine version change
// shows while it rolls out.
func (o *observation) rollingOutImage() bool {
	for i := range o.pods {
		if c := findContainer(o.pods[i].Spec.Containers, mariadbContainerName); c != nil && c.Image != o.mdb.Spec.Image {
			return true
		}
	}
	return false
}

// availability says whether clients can connect. Galera takes reads and
// writes on any synced node, which is what its readiness probe checks;
// standalone and replication take writes on their primary only. With a
// MaxScale proxy, clients connect through it, so a proxy pod must be ready
// too.
//
// It reads pod readiness from the cache, so it is as fresh as the last pod
// event the provider has seen.
func (o *observation) availability() (controller.Availability, string, string) {
	switch {
	case o.restore != nil && o.restore.seeding:
		return controller.Unavailable, corev1alpha1.ReasonLoadingData, "The instance is being seeded from its data source"
	case o.restore != nil:
		return controller.Unavailable, reasonRestoring, "A restore is replacing the data"
	case o.rotatingRoot:
		return controller.Unavailable, reasonRotatingRootPassword, "The root password copied from the snapshot's source is being replaced"
	case o.sts == nil:
		return controller.Unavailable, reasonNotCreated, "The MariaDB pods have not been created"
	}

	if o.mdb.IsGaleraEnabled() {
		if !slices.ContainsFunc(o.pods, isPodReady) {
			return controller.Unavailable, reasonNoNodeReady, "No Galera node is ready"
		}
	} else {
		primary := o.mdb.Status.CurrentPrimary
		if primary == nil || *primary == "" {
			return controller.AvailabilityUnknown, reasonPrimaryNotReported, "The operator has not reported which pod is the primary"
		}
		i := slices.IndexFunc(o.pods, func(p corev1.Pod) bool { return p.Name == *primary })
		if i < 0 || !isPodReady(o.pods[i]) {
			return controller.Unavailable, reasonNoPrimary, fmt.Sprintf("The primary pod %s is not ready", *primary)
		}
	}

	if p := o.proxy; p != nil && (p.sts == nil || p.sts.Status.ReadyReplicas == 0) {
		return controller.Unavailable, reasonNoProxyReady, "No MaxScale proxy pod is ready"
	}
	// The published credentials are the initial user's: until it can log in,
	// clients given them cannot connect.
	if o.userWait != "" {
		return controller.Unavailable, reasonInitialUserNotReady, o.userWait
	}
	return controller.Available, "", ""
}

const maxScaleContainerName = "maxscale"

func findContainer(containers []corev1.Container, name string) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

func isPodReady(pod corev1.Pod) bool {
	if !pod.DeletionTimestamp.IsZero() {
		return false
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

func ptrInt32(p *int32, def int32) int32 {
	if p == nil {
		return def
	}
	return *p
}

// enqueueOperatorChildInstance maps an object the operator creates for the
// database or its MaxScale proxy (a StatefulSet, the initial User or Grant)
// to the Instance, whose status depends on it. They are owned by the MariaDB
// or MaxScale object, whose name is derived from the Instance's.
func enqueueOperatorChildInstance() func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(_ context.Context, obj client.Object) []reconcile.Request {
		owner := metav1.GetControllerOf(obj)
		if owner == nil || !strings.HasPrefix(owner.APIVersion, mariadbv1alpha1.GroupVersion.Group+"/") {
			return nil
		}
		var instance string
		switch owner.Kind {
		case "MariaDB":
			instance = owner.Name
		case "MaxScale":
			instance = strings.TrimSuffix(owner.Name, maxScaleName(""))
			if instance == owner.Name {
				return nil
			}
		default:
			return nil
		}
		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: instance},
		}}
	}
}

// enqueueRestoreInstance maps a Restore to the Instance it targets, so the
// Instance stops reporting a restore as soon as it reaches a terminal state.
func enqueueRestoreInstance() func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(_ context.Context, obj client.Object) []reconcile.Request {
		restore, ok := obj.(*backupv1alpha1.Restore)
		if !ok || restore.Spec.InstanceRef.Name == "" {
			return nil
		}
		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{Namespace: restore.Namespace, Name: restore.Spec.InstanceRef.Name},
		}}
	}
}
