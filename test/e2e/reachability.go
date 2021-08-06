// Copyright 2020 Antrea Authors
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

package e2e

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Pod string

type CustomPod struct {
	Pod    Pod
	Labels map[string]string
}

func NewPod(namespace string, podName string) Pod {
	return Pod(fmt.Sprintf("%s/%s", namespace, podName))
}

func (pod Pod) String() string {
	return string(pod)
}

func (pod Pod) split() (string, string) {
	pieces := strings.Split(string(pod), "/")
	if len(pieces) != 2 {
		panic(fmt.Errorf("expected ns/pod, found %+v", pieces))
	}
	return pieces[0], pieces[1]
}

func (pod Pod) Namespace() string {
	ns, _ := pod.split()
	return ns
}

func (pod Pod) PodName() string {
	_, podName := pod.split()
	return podName
}

type PodConnectivityMark string

const (
	Connected PodConnectivityMark = "Con"
	Unknown   PodConnectivityMark = "Unk"
	Error     PodConnectivityMark = "Err"
	Dropped   PodConnectivityMark = "Drp"
	Rejected  PodConnectivityMark = "Rej"
)

type Connectivity struct {
	From         Pod
	To           Pod
	Connectivity PodConnectivityMark
}

type ConnectivityTable struct {
	Items   []string
	itemSet map[string]bool
	Values  map[string]map[string]PodConnectivityMark
}

type TruthTable struct {
	Items   []string
	itemSet map[string]bool
	Values  map[string]map[string]bool
}

func NewConnectivityTable(items []string, defaultValue *PodConnectivityMark) *ConnectivityTable {
	itemSet := map[string]bool{}
	values := map[string]map[string]PodConnectivityMark{}
	for _, from := range items {
		itemSet[from] = true
		values[from] = map[string]PodConnectivityMark{}
		if defaultValue != nil {
			for _, to := range items {
				values[from][to] = *defaultValue
			}
		}
	}
	return &ConnectivityTable{
		Items:   items,
		itemSet: itemSet,
		Values:  values,
	}
}

// IsComplete returns true if there's a value set for every single pair of items, otherwise it returns false.
func (tt *TruthTable) IsComplete() bool {
	for _, from := range tt.Items {
		for _, to := range tt.Items {
			if _, ok := tt.Values[from][to]; !ok {
				return false
			}
		}
	}
	return true
}

func (ct *ConnectivityTable) Set(from string, to string, value PodConnectivityMark) {
	dict, ok := ct.Values[from]
	if !ok {
		panic(fmt.Errorf("key %s not found in map", from))
	}
	if _, ok := ct.itemSet[to]; !ok {
		panic(fmt.Errorf("key %s not allowed", to))
	}
	dict[to] = value
}

func (ct *ConnectivityTable) SetAllFrom(from string, value PodConnectivityMark) {
	dict, ok := ct.Values[from]
	if !ok {
		panic(fmt.Errorf("key %s not found in map", from))
	}
	for _, to := range ct.Items {
		dict[to] = value
	}
}

func (ct *ConnectivityTable) SetAllTo(to string, value PodConnectivityMark) {
	if _, ok := ct.itemSet[to]; !ok {
		panic(fmt.Errorf("key %s not found", to))
	}
	for _, from := range ct.Items {
		ct.Values[from][to] = value
	}
}

func (ct *ConnectivityTable) Get(from string, to string) PodConnectivityMark {
	dict, ok := ct.Values[from]
	if !ok {
		return Unknown
	}
	val, ok := dict[to]
	if !ok {
		return Unknown
	}
	return val
}

func (ct *ConnectivityTable) Compare(other *ConnectivityTable) *TruthTable {
	// TODO set equality
	// if tt.itemSet != other.itemSet {
	//	panic()
	// }
	values := map[string]map[string]bool{}
	for from, dict := range ct.Values {
		values[from] = map[string]bool{}
		for to, val := range dict {
			values[from][to] = val == other.Values[from][to] // TODO other.Get(from, to) ?
		}
	}
	// TODO check for equality from both sides
	return &TruthTable{
		Items:   ct.Items,
		itemSet: ct.itemSet,
		Values:  values,
	}
}

func (ct *ConnectivityTable) PrettyPrint(indent string) string {
	header := indent + strings.Join(append([]string{"-"}, ct.Items...), "\t")
	lines := []string{header}
	for _, from := range ct.Items {
		line := []string{from}
		for _, to := range ct.Items {
			val := fmt.Sprintf("%s", ct.Values[from][to])
			line = append(line, val)
		}
		lines = append(lines, indent+strings.Join(line, "\t"))
	}
	return strings.Join(lines, "\n")
}

func (tt *TruthTable) PrettyPrint(indent string) string {
	header := indent + strings.Join(append([]string{"-"}, tt.Items...), "\t")
	lines := []string{header}
	for _, from := range tt.Items {
		line := []string{from}
		for _, to := range tt.Items {
			val := "X"
			if tt.Values[from][to] {
				val = "."
			}
			line = append(line, val)
		}
		lines = append(lines, indent+strings.Join(line, "\t"))
	}
	return strings.Join(lines, "\n")
}

type Reachability struct {
	Expected        *ConnectivityTable
	Observed        *ConnectivityTable
	Pods            []Pod
	PodsByNamespace map[string][]Pod
}

func NewReachability(pods []Pod, defaultExpectation PodConnectivityMark) *Reachability {
	var items []string
	podsByNamespace := make(map[string][]Pod)
	for _, pod := range pods {
		items = append(items, string(pod))
		podNS := pod.Namespace()
		podsByNamespace[podNS] = append(podsByNamespace[podNS], pod)
	}
	r := &Reachability{
		Expected:        NewConnectivityTable(items, &defaultExpectation),
		Observed:        NewConnectivityTable(items, nil),
		Pods:            pods,
		PodsByNamespace: podsByNamespace,
	}
	return r
}

// ExpectConn is an experimental way to describe connectivity with named fields
func (r *Reachability) ExpectConn(spec *Connectivity) {
	if spec.From == "" && spec.To == "" {
		panic("at most one of From and To may be empty, but both are empty")
	}
	if spec.From == "" {
		r.ExpectAllIngress(spec.To, spec.Connectivity)
	} else if spec.To == "" {
		r.ExpectAllEgress(spec.From, spec.Connectivity)
	} else {
		r.Expect(spec.From, spec.To, spec.Connectivity)
	}
}

func (r *Reachability) Expect(pod1 Pod, pod2 Pod, connectivity PodConnectivityMark) {
	r.Expected.Set(string(pod1), string(pod2), connectivity)
}

func (r *Reachability) ExpectSelf(allPods []Pod, connectivity PodConnectivityMark) {
	for _, p := range allPods {
		r.Expected.Set(string(p), string(p), connectivity)
	}
}

// ExpectAllIngress defines that any traffic going into the pod will be allowed/dropped/rejected
func (r *Reachability) ExpectAllIngress(pod Pod, connectivity PodConnectivityMark) {
	r.Expected.SetAllTo(string(pod), connectivity)
	if connectivity != Connected {
		log.Infof("Denying all traffic *to* %s", pod)
	}
}

// ExpectAllEgress defines that any traffic going out of the pod will be allowed/dropped/rejected
func (r *Reachability) ExpectAllEgress(pod Pod, connectivity PodConnectivityMark) {
	r.Expected.SetAllFrom(string(pod), connectivity)
	if connectivity != Connected {
		log.Infof("Denying all traffic *from* %s", pod)
	}
}

func (r *Reachability) ExpectAllSelfNamespace(connectivity PodConnectivityMark) {
	for _, pods := range r.PodsByNamespace {
		for i := range pods {
			for j := range pods {
				r.Expected.Set(string(pods[i]), string(pods[j]), connectivity)
			}
		}
	}
}

func (r *Reachability) ExpectSelfNamespace(namespace string, connectivity PodConnectivityMark) {
	pods, ok := r.PodsByNamespace[namespace]
	if !ok {
		panic(fmt.Errorf("namespace %s is not found", namespace))
	}
	for i := range pods {
		for j := range pods {
			r.Expected.Set(string(pods[i]), string(pods[j]), connectivity)
		}
	}
}

func (r *Reachability) ExpectIngressFromNamespace(pod Pod, namespace string, connectivity PodConnectivityMark) {
	pods, ok := r.PodsByNamespace[namespace]
	if !ok {
		panic(fmt.Errorf("namespace %s is not found", namespace))
	}
	for i := range pods {
		r.Expected.Set(string(pods[i]), string(pod), connectivity)
	}
}

func (r *Reachability) ExpectEgressToNamespace(pod Pod, namespace string, connectivity PodConnectivityMark) {
	pods, ok := r.PodsByNamespace[namespace]
	if !ok {
		panic(fmt.Errorf("namespace %s is not found", namespace))
	}
	for i := range pods {
		r.Expected.Set(string(pod), string(pods[i]), connectivity)
	}
}

func (r *Reachability) Observe(pod1 Pod, pod2 Pod, connectivity PodConnectivityMark) {
	r.Observed.Set(string(pod1), string(pod2), connectivity)
}

func (r *Reachability) Summary() (trueObs int, falseObs int, comparison *TruthTable) {
	comparison = r.Expected.Compare(r.Observed)
	if !comparison.IsComplete() {
		panic("observations not complete!")
	}
	falseObs = 0
	trueObs = 0
	for _, dict := range comparison.Values {
		for _, val := range dict {
			if val {
				trueObs++
			} else {
				falseObs++
			}
		}
	}
	return trueObs, falseObs, comparison
}

func (r *Reachability) PrintSummary(printExpected bool, printObserved bool, printComparison bool) {
	right, wrong, comparison := r.Summary()
	fmt.Printf("reachability: correct:%v, incorrect:%v, result=%t\n\n", right, wrong, wrong == 0)
	if printExpected {
		fmt.Printf("expected:\n\n%s\n\n\n", r.Expected.PrettyPrint(""))
	}
	if printObserved {
		fmt.Printf("observed:\n\n%s\n\n\n", r.Observed.PrettyPrint(""))
	}
	if printComparison {
		fmt.Printf("comparison:\n\n%s\n\n\n", comparison.PrettyPrint(""))
	}
}
