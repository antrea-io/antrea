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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Pod string

func NewPod(namespace string, podName string) Pod {
	return Pod(fmt.Sprintf("%s/%s", namespace, podName))
}

func (pod Pod) String() string {
	return string(pod)
}

func (pod Pod) split() (string, string) {
	pieces := strings.Split(string(pod), "/")
	if len(pieces) != 2 {
		panic(errors.New(fmt.Sprintf("expected ns/pod, found %+v", pieces)))
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

type Connectivity struct {
	From        Pod
	To          Pod
	IsConnected bool
}

type TruthTable struct {
	Items   []string
	itemSet map[string]bool
	Values  map[string]map[string]bool
}

func NewTruthTable(items []string, defaultValue *bool) *TruthTable {
	itemSet := map[string]bool{}
	values := map[string]map[string]bool{}
	for _, from := range items {
		itemSet[from] = true
		values[from] = map[string]bool{}
		if defaultValue != nil {
			for _, to := range items {
				values[from][to] = *defaultValue
			}
		}
	}
	return &TruthTable{
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

func (tt *TruthTable) Set(from string, to string, value bool) {
	dict, ok := tt.Values[from]
	if !ok {
		panic(errors.New(fmt.Sprintf("key %s not found in map", from)))
	}
	if _, ok := tt.itemSet[to]; !ok {
		panic(errors.New(fmt.Sprintf("key %s not allowed", to)))
	}
	dict[to] = value
}

func (tt *TruthTable) SetAllFrom(from string, value bool) {
	dict, ok := tt.Values[from]
	if !ok {
		panic(errors.New(fmt.Sprintf("key %s not found in map", from)))
	}
	for _, to := range tt.Items {
		dict[to] = value
	}
}

func (tt *TruthTable) SetAllTo(to string, value bool) {
	if _, ok := tt.itemSet[to]; !ok {
		panic(errors.New(fmt.Sprintf("key %s not found", to)))
	}
	for _, from := range tt.Items {
		tt.Values[from][to] = value
	}
}

func (tt *TruthTable) Get(from string, to string) bool {
	dict, ok := tt.Values[from]
	if !ok {
		panic(errors.New(fmt.Sprintf("key %s not found in map", from)))
	}
	val, ok := dict[to]
	if !ok {
		panic(errors.New(fmt.Sprintf("key %s not found in map (%+v)", to, dict)))
	}
	return val
}

func (tt *TruthTable) Compare(other *TruthTable) *TruthTable {
	// TODO set equality
	//if tt.itemSet != other.itemSet {
	//	panic()
	//}
	values := map[string]map[string]bool{}
	for from, dict := range tt.Values {
		values[from] = map[string]bool{}
		for to, val := range dict {
			values[from][to] = val == other.Values[from][to] // TODO other.Get(from, to) ?
		}
	}
	// TODO check for equality from both sides
	return &TruthTable{
		Items:   tt.Items,
		itemSet: tt.itemSet,
		Values:  values,
	}
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
	Expected *TruthTable
	Observed *TruthTable
	Pods     []Pod
}

func NewReachability(pods []Pod, defaultExpectation bool) *Reachability {
	items := []string{}
	for _, pod := range pods {
		items = append(items, string(pod))
	}
	r := &Reachability{
		Expected: NewTruthTable(items, &defaultExpectation),
		Observed: NewTruthTable(items, nil),
		Pods:     pods,
	}
	return r
}

// ExpectConn is an experimental way to describe connectivity with named fields
func (r *Reachability) ExpectConn(spec *Connectivity) {
	if spec.From == "" && spec.To == "" {
		panic("at most one of From and To may be empty, but both are empty")
	}
	if spec.From == "" {
		r.ExpectAllIngress(spec.To, spec.IsConnected)
	} else if spec.To == "" {
		r.ExpectAllEgress(spec.From, spec.IsConnected)
	} else {
		r.Expect(spec.From, spec.To, spec.IsConnected)
	}
}

func (r *Reachability) Expect(pod1 Pod, pod2 Pod, isConnected bool) {
	r.Expected.Set(string(pod1), string(pod2), isConnected)
}

func (r *Reachability) ExpectSelf(allPods []Pod, isConnected bool) {
	for _, p := range allPods {
		r.Expected.Set(string(p), string(p), isConnected)
	}
}

// ExpectAllIngress defines that any traffic going into the pod will be allowed/denied (true/false)
func (r *Reachability) ExpectAllIngress(pod Pod, connected bool) {
	r.Expected.SetAllTo(string(pod), connected)
	if !connected {
		log.Infof("Denying all traffic *to* %s", pod)
	}
}

// ExpectAllEgress defines that any traffic going out of the pod will be allowed/denied (true/false)
func (r *Reachability) ExpectAllEgress(pod Pod, connected bool) {
	r.Expected.SetAllFrom(string(pod), connected)
	if !connected {
		log.Infof("Denying all traffic *from* %s", pod)
	}
}

func (r *Reachability) Observe(pod1 Pod, pod2 Pod, isConnected bool) {
	r.Observed.Set(string(pod1), string(pod2), isConnected)
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
