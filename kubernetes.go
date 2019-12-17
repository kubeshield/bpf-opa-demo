/*
Copyright The Pharmer Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"sync"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var (
	PodMapMutex = sync.RWMutex{}
	PodMap      = make(map[string]*v1.Pod)
)

func SetupPodWatcher() error {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		return err
	}

	newPodWatcher := &PodWatcher{
		Client: mgr.GetClient(),
		Log:    klogr.New().WithName("podwatcher"),
	}
	if err := newPodWatcher.SetupWithManager(mgr, controller.Options{}); err != nil {
		return err
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return err
	}

	return nil
}

type PodWatcher struct {
	Client client.Client
	Log    logr.Logger
}

func (p *PodWatcher) SetupWithManager(mgr ctrl.Manager, options controller.Options) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1.Pod{}).
		WithOptions(options).
		Complete(p)
	if err != nil {
		return errors.Wrap(err, "failed setting up with a controller manager")
	}

	return nil
}

func (p *PodWatcher) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	log := p.Log.WithValues("name", req.Name, "namespace", req.Namespace)

	pod := &v1.Pod{}
	if err := p.Client.Get(context.Background(), req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get pod")
		return ctrl.Result{}, err
	}

	// if delete event, remove from pod map
	if pod.DeletionTimestamp != nil {
		PodMapMutex.Lock()
		for _, container := range pod.Status.ContainerStatuses {
			delete(PodMap, container.ContainerID)
		}
		PodMapMutex.Unlock()
		return ctrl.Result{}, nil
	}

	// create/update event, update the podmap
	PodMapMutex.Lock()
	for _, container := range pod.Status.ContainerStatuses {
		if len(container.ContainerID) >= 64 {
			id := container.ContainerID[len(container.ContainerID)-64:]
			PodMap[id] = pod
		}
	}
	PodMapMutex.Unlock()

	return ctrl.Result{}, nil
}
