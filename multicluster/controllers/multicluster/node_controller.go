/*
Copyright 2022 Antrea Authors.

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

package multicluster

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

type (
	// NodeReconciler is for member cluster only.
	// It will create a Gateway object if a Node has an annotation `multicluster.antrea.io/gateway:true`
	// and update corresponding Gateway if any subnets changes.
	NodeReconciler struct {
		client.Client
		Scheme     *runtime.Scheme
		namespace  string
		precedence mcsv1alpha1.Precedence
	}
)

// NewNodeReconciler creates a NodeReconciler to watch Node object changes and create a
// corresponding Gateway if the Node has the annotation `multicluster.antrea.io/gateway:true`.
func NewNodeReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	namespace string,
	precedence mcsv1alpha1.Precedence) *NodeReconciler {
	if string(precedence) == "" {
		precedence = mcsv1alpha1.PrecedenceInternal
	}
	reconciler := &NodeReconciler{
		Client:     client,
		Scheme:     scheme,
		namespace:  namespace,
		precedence: precedence,
	}
	return reconciler
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=gateways/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=gateways/finalizers,verbs=update

func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling Node", "node", req.Name)
	gw := &mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: r.namespace,
		},
	}
	// When the Node is annotated with 'multicluster.antrea.io/gateway=true' as a Gateway:
	//   - Delete the Gateway if the Node is deleted
	//   - Update the Gateway if Node's InternalIP or GatewayIP is updated
	//   - Create a new Gateway if there is no existing Gateway
	node := &corev1.Node{}
	if err := r.Client.Get(ctx, req.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			err := r.Client.Delete(ctx, gw, &client.DeleteOptions{})
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		klog.ErrorS(err, "Failed to get Node", "node", req.Name)
		return ctrl.Result{}, err
	}

	_, isGW := node.Annotations[common.GatewayAnnotation]
	var err error
	gwNamespacedName := types.NamespacedName{
		Name:      node.Name,
		Namespace: r.namespace,
	}

	// TODO: cache might be stale. Need to revisit here and other reconcilers to
	// check if we can improve this with 'Owns' or other methods.
	var gwIP, internalIP string
	if isGW {
		if internalIP, gwIP, err = r.getGatawayNodeIP(node); err != nil {
			klog.ErrorS(err, "There is no valid Gateway IP for Node, will retry later when there is any new Node update", "node", node.Name)
			return ctrl.Result{}, nil
		}
	}
	if err := r.Client.Get(ctx, gwNamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) && isGW {
			gw.GatewayIP = gwIP
			gw.InternalIP = internalIP
			if err := r.Client.Create(ctx, gw, &client.CreateOptions{}); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !isGW {
		err := r.Client.Delete(ctx, gw, &client.DeleteOptions{})
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	gw.GatewayIP = gwIP
	gw.InternalIP = internalIP
	if err := r.Client.Update(ctx, gw, &client.UpdateOptions{}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NodeReconciler) getGatawayNodeIP(node *corev1.Node) (string, string, error) {
	var gatewayIP, internalIP string
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			if r.precedence == mcsv1alpha1.PrecedencePrivate || r.precedence == mcsv1alpha1.PrecedenceInternal {
				gatewayIP = addr.Address
			}
			internalIP = addr.Address
		}
		if (r.precedence == mcsv1alpha1.PrecedencePublic || r.precedence == mcsv1alpha1.PrecedenceExternal) &&
			addr.Type == corev1.NodeExternalIP {
			gatewayIP = addr.Address
		}
	}

	if ip, ok := node.Annotations[common.GatewayIPAnnotation]; ok {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return "", "", fmt.Errorf("the Gateway IP annotation %s on Node %s is not a valid IP address", ip, node.Name)
		}
		gatewayIP = ip
	}

	if gatewayIP == "" || internalIP == "" {
		return "", "", fmt.Errorf("no valid IP address for Gateway Node %s", node.Name)
	}
	return internalIP, gatewayIP, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
