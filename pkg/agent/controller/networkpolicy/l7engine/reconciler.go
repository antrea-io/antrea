// Copyright 2022 Antrea Authors
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

package l7engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	v1beta "antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/v2/pkg/util/logdir"
	utilsync "antrea.io/antrea/v2/pkg/util/sync"
)

const (
	defaultSuricataConfigPath = "/etc/suricata/suricata.yaml"
	antreaSuricataConfigPath  = "/etc/suricata/antrea.yaml"
	antreaSuricataLogSubdir   = "networkpolicy/l7engine"

	rulesDir  = "/etc/suricata/rules"
	rulesPath = rulesDir + "/antrea-l7-networkpolicy.rules"

	suricataCommandSocket = "/var/run/suricata/suricata-command.socket"

	protocolHTTP = "http"
	protocolTLS  = "tls"

	scCmdOK = "OK"

	// Every L7 rule tags the traffic it applies to with a flowbit derived from its VLAN ID, and with
	// flowbitAll. The former scopes the rules of an L7 rule to its own traffic, the latter lets a
	// single rule reject the traffic which belongs to no L7 rule.
	flowbitAll    = "antrea_l7"
	flowbitPrefix = "antrea_l7_"

	// Set by the allow rules of every L7 rule, so that the bounds below stop applying to a flow which
	// has been allowed.
	flowbitAllowed = "antrea_l7_allowed"

	// SID of the rule which belongs to no L7 rule. The rules of the L7 rules are numbered from the one
	// after it.
	commonRulesSID = 1

	// How much a flow may send, and for how long, without any of the L7 rule's allow rules having
	// matched it.
	//
	// A protocol the engine never identifies is never rejected on its merits, because the rules doing
	// that wait for an identification which only concludes once either side has sent data. A client
	// sending bytes of no known protocol to a peer which does not answer is the common case, and it
	// needs no malice: a Go HTTP server reading a request line blocks until it sees one, so sending it
	// anything without a newline leaves both sides waiting and the flow unidentified for as long as it
	// is held open.
	//
	// The two bound different things and both are needed. Time alone does not bound volume, since a
	// flow can send as fast as the link allows before it expires. Volume alone does not bound a flow
	// which trickles, and cannot be set low enough to, because the bytes it counts are the request
	// line and the headers of a request which is about to be allowed.
	//
	// A flow is exempt from both as soon as an allow rule has matched it, so they bound what a flow
	// can do before it is examined, not what it can do at all. A request which is allowed keeps its
	// connection for as long as it likes, however large its body, and a keep-alive connection stays
	// allowed for its later requests.
	//
	// The volume values are above the request line and header limits of common servers, 8 KiB for the
	// request line in Apache and nginx and 32 KiB or less in total headers, so they cut nothing a
	// server would have served. The TLS value is the size of one TLS record, which every real client
	// hello fits in several times over.
	maxUnmatchedFlowAgeSeconds = 5
	maxUnmatchedBytesHTTP      = 65536
	maxUnmatchedBytesTLS       = 16384
)

type scCmdRet struct {
	Message string `json:"message"`
	Return  string `json:"return"`
}

var (
	// Declared as a variable for testing.
	defaultFS = afero.NewOsFs()

	// Create the config file /etc/suricata/antrea.yaml for Antrea which will be included in the default Suricata config file
	// /etc/suricata/suricata.yaml. Two event logs in the config serve alert gilogging and http event logging purposes respectively.
	suricataAntreaConfigData = fmt.Sprintf(`%%YAML 1.1
---
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-%%Y-%%m-%%d.json
      rotate-interval: day
      pcap-file: false
      community-id: false
      community-id-seed: 0
      xff:
        enabled: no
      types:
        - alert:
            packet: yes
        - http:
            extended: yes
        - tls:
            extended: yes
af-packet:
  - interface: %[1]s
    threads: auto
    cluster-id: 80
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    copy-mode: ips
    copy-iface: %[2]s
  - interface:  %[2]s
    threads: auto
    cluster-id: 81
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    copy-mode: ips
    copy-iface: %[1]s
default-rule-path: %[3]s
rule-files:
  - %[4]s
`, config.L7RedirectTargetPortName, config.L7RedirectReturnPortName, rulesDir, rulesPath)

	// The rules which belong to no L7 rule. Traffic reaching Suricata is always tagged with a VLAN ID
	// by the OVS pipeline, so the rule below should never match, but the rejection is written out
	// rather than left to Suricata, which has no default deny for traffic whose protocol it never
	// identifies.
	commonRulesData = fmt.Sprintf(`reject ip any any -> any any (msg: "Reject by Antrea L7 NetworkPolicy: traffic belongs to no rule"; flow: to_server, established; flowbits: isnotset,%s; sid: %d;)
`, flowbitAll, commonRulesSID)
)

// l7Rule is what one L7 rule contributes to the Suricata rules file. What it contributes is rendered
// when the file is written rather than when the rule is added, because a rule's SIDs depend on how
// many rules precede it in the file.
type l7Rule struct {
	policyName    string
	vlanID        uint32
	protoKeywords map[string]sets.Set[string]
}

type Reconciler struct {
	// Declared as member variables for testing.
	startSuricataFn func()
	suricataScFn    func(scCmd string) (*scCmdRet, error)

	// rulesMutex protects rulesByVlanID and rulesChanged. All the L7 rules share one Suricata rules
	// file, so a change to any of them rewrites the whole file.
	rulesMutex    sync.Mutex
	rulesByVlanID map[uint32]*l7Rule
	// rulesChanged is set when rulesByVlanID has changed since the rules file was last written and
	// reloaded, and cleared when a sync starts from the current content.
	rulesChanged bool

	// syncMutex serializes writing the rules file and reloading Suricata. A caller which finds it held
	// waits, and by the time it acquires it the sync which was in flight may already have included the
	// caller's change, in which case rulesChanged is clear and there is nothing left to do. Under a
	// burst of changes, such as every L7 rule being added when the agent starts, this keeps the number
	// of reloads to a couple rather than one per change.
	syncMutex sync.Mutex

	ofClient openflow.Client

	startSuricataOnce     utilsync.OnceWithNoError
	initializeL7FlowsOnce utilsync.OnceWithNoError
}

func NewReconciler(ofClient openflow.Client) *Reconciler {
	return &Reconciler{
		suricataScFn:    suricataSc,
		startSuricataFn: startSuricata,
		rulesByVlanID:   make(map[uint32]*l7Rule),
		ofClient:        ofClient,
	}
}

func flowbitForVlanID(vlanID uint32) string {
	return fmt.Sprintf("%s%d", flowbitPrefix, vlanID)
}

// deferredRejectHooks is the Suricata rule hook at which an L7 rule rejects the traffic of each
// protocol. The hook matters: a rejection evaluated before the request line or the client
// hello has been parsed terminates the connection while the criteria to allow it are still unknown,
// which is why a request larger than the MTU used to be rejected. Each hook below is only reached
// once the parser has the fields the allow rules match on.
var deferredRejectHooks = map[string]string{
	protocolHTTP: "http1:request_headers",
	protocolTLS:  "tls:client_hello_done",
}

// maxUnmatchedBytes is the volume bound described above for each protocol. An L7 rule allowing more
// than one protocol uses the largest of them.
var maxUnmatchedBytes = map[string]int{
	protocolHTTP: maxUnmatchedBytesHTTP,
	protocolTLS:  maxUnmatchedBytesTLS,
}

// writeRules writes the Suricata rules enforcing one L7 rule, numbered from sid, and returns the
// next free SID.
//
// Suricata refuses a signature combining a packet level match such as vlan.id with an application
// layer match, so the VLAN ID allocated to the L7 rule is turned into a flowbit by a packet level
// rule, and every other rule of the L7 rule matches on that flowbit. This is what keeps the rules of
// one L7 rule from matching the traffic of another.
func writeRules(rulesData *bytes.Buffer, rule *l7Rule, sid int) int {
	flowbit := flowbitForVlanID(rule.vlanID)

	// Tag the traffic of this L7 rule. The rule carries no application layer match, otherwise Suricata
	// would refuse it.
	fmt.Fprintf(rulesData, `alert ip any any -> any any (vlan.id: %d; flowbits: set,%s; flowbits: set,%s; flowbits: noalert; sid: %d;)`+"\n",
		rule.vlanID, flowbit, flowbitAll, sid)
	sid++

	protocols := sets.List(sets.KeySet(rule.protoKeywords))

	// Reject the traffic whose protocol is not one this L7 rule allows. A flow whose protocol Suricata
	// never identifies matches neither this rule nor the next one, the two bounds after them cover it.
	var notProtocols []string
	for _, proto := range protocols {
		notProtocols = append(notProtocols, fmt.Sprintf("app-layer-protocol: !%s;", proto))
	}
	fmt.Fprintf(rulesData, `reject ip any any -> any any (msg: "Reject by %s"; flowbits: isset,%s; flow: to_server, established; %s sid: %d;)`+"\n",
		rule.policyName, flowbit, strings.Join(notProtocols, " "), sid)
	sid++
	fmt.Fprintf(rulesData, `reject ip any any -> any any (msg: "Reject by %s"; flowbits: isset,%s; flow: to_server, established; app-layer-protocol: failed; sid: %d;)`+"\n",
		rule.policyName, flowbit, sid)
	sid++

	// Reject a flow which no allow rule has matched, once it has sent enough or lasted long enough.
	// This is what covers a flow whose protocol is never identified, see the comment on
	// maxUnmatchedFlowAgeSeconds.
	maxBytes := 0
	for _, proto := range protocols {
		if maxUnmatchedBytes[proto] > maxBytes {
			maxBytes = maxUnmatchedBytes[proto]
		}
	}
	fmt.Fprintf(rulesData, `reject ip any any -> any any (msg: "Reject by %s"; flowbits: isset,%s; flowbits: isnotset,%s; flow: to_server, established; flow.bytes_toserver: >%d; sid: %d;)`+"\n",
		rule.policyName, flowbit, flowbitAllowed, maxBytes, sid)
	sid++
	fmt.Fprintf(rulesData, `reject ip any any -> any any (msg: "Reject by %s"; flowbits: isset,%s; flowbits: isnotset,%s; flow: to_server, established; flow.age: >%d; sid: %d;)`+"\n",
		rule.policyName, flowbit, flowbitAllowed, maxUnmatchedFlowAgeSeconds, sid)
	sid++

	// Reject the traffic of an allowed protocol which none of the allow rules below matches. A protocol
	// whose criteria are empty allows all of its traffic, so there is nothing left for this rule to
	// reject and emitting it would only rely on the allow rule outranking it.
	for _, proto := range protocols {
		if rule.protoKeywords[proto].Has("") {
			continue
		}
		fmt.Fprintf(rulesData, `reject %s any any -> any any (msg: "Reject by %s"; flowbits: isset,%s; sid: %d;)`+"\n",
			deferredRejectHooks[proto], rule.policyName, flowbit, sid)
		sid++
	}

	// Allow the traffic matching the criteria of the L7 rule.
	for _, proto := range protocols {
		for _, keywords := range sets.List(rule.protoKeywords[proto]) {
			// It is a convention that the sid is provided as the last keyword (or second-to-last if there is a rev)
			// of a rule.
			allKeywords := fmt.Sprintf(`msg: "Allow %s by %s"; flowbits: isset,%s; flowbits: set,%s; sid: %d;`, proto, rule.policyName, flowbit, flowbitAllowed, sid)
			if keywords != "" {
				allKeywords = fmt.Sprintf(`msg: "Allow %s by %s"; flowbits: isset,%s; flowbits: set,%s; %s sid: %d;`, proto, rule.policyName, flowbit, flowbitAllowed, keywords, sid)
			}
			fmt.Fprintf(rulesData, "pass %s any any -> any any (%s)\n", proto, allKeywords)
			sid++
		}
	}

	return sid
}

func writeConfigFile(path string, data *bytes.Buffer) error {
	f, err := defaultFS.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data.Bytes()); err != nil {
		return err
	}
	return nil
}

// By default, Suricata performs pattern-matching for provided content. To support exact match, prefix match, and suffix
// match, we use wildcards to indicate whether an exact match is expected.
// - A string starting with * means suffix match. For example, "*.foo.com" matches "www.foo.com".
// - A string ending with * means prefix match. For example, "/public/*" matches "/public/index.html".
// - A string starting with and ending with * means pattern-matching. For example, "*/v2/*" matches "/api/v2/pods".
// - A string having no * means exact match. For example, "/index.html" can only match "/index.html".
func convertContent(content string) string {
	startsWith := " startswith;"
	if strings.HasPrefix(content, "*") {
		startsWith = ""
		content = content[1:]
	}
	endsWith := " endswith;"
	if strings.HasSuffix(content, "*") {
		endsWith = ""
		content = content[:len(content)-1]
	}
	return fmt.Sprintf(`content:"%s";%s%s`, content, startsWith, endsWith)
}

func convertProtocolHTTP(http *v1beta.HTTPProtocol) string {
	var keywords []string
	if http.Path != "" {
		keywords = append(keywords, fmt.Sprintf("http.uri; %s", convertContent(http.Path)))
	}
	if http.Method != "" {
		keywords = append(keywords, fmt.Sprintf(`http.method; content:"%s";`, http.Method))
	}
	if http.Host != "" {
		keywords = append(keywords, fmt.Sprintf("http.host; %s", convertContent(http.Host)))
	}
	return strings.Join(keywords, " ")
}

func convertProtocolTLS(tls *v1beta.TLSProtocol) string {
	var keywords []string
	if tls.SNI != "" {
		keywords = append(keywords, fmt.Sprintf("tls.sni; %s", convertContent(tls.SNI)))
	}
	return strings.Join(keywords, " ")
}

func (r *Reconciler) StartSuricataOnce() error {
	return r.startSuricataOnce.Do(r.startSuricata)
}

func (r *Reconciler) initializeL7Flows() error {
	if err := r.ofClient.InstallL7NetworkPolicyFlows(); err != nil {
		return fmt.Errorf("failed to install L7 NetworkPolicy flows: %w", err)
	}
	return nil
}

func (r *Reconciler) AddRule(ruleID, policyName string, vlanID uint32, l7Protocols []v1beta.L7Protocol) error {
	start := time.Now()
	defer func() {
		klog.V(5).Infof("AddRule took %v", time.Since(start))
	}()

	if err := r.StartSuricataOnce(); err != nil {
		return err
	}
	if err := r.initializeL7FlowsOnce.Do(r.initializeL7Flows); err != nil {
		return err
	}

	// Generate the keyword part used in Suricata rules.
	protoKeywords := make(map[string]sets.Set[string])
	for _, protocol := range l7Protocols {
		if protocol.HTTP != nil {
			httpKeywords := convertProtocolHTTP(protocol.HTTP)
			if _, ok := protoKeywords[protocolHTTP]; !ok {
				protoKeywords[protocolHTTP] = sets.New[string]()
			}
			protoKeywords[protocolHTTP].Insert(httpKeywords)
		}
		if protocol.TLS != nil {
			tlsKeywords := convertProtocolTLS(protocol.TLS)
			if _, ok := protoKeywords[protocolTLS]; !ok {
				protoKeywords[protocolTLS] = sets.New[string]()
			}
			protoKeywords[protocolTLS].Insert(tlsKeywords)
		}
	}

	klog.InfoS("Reconciling L7 rule", "RuleID", ruleID, "PolicyName", policyName)
	rule := &l7Rule{
		policyName:    policyName,
		vlanID:        vlanID,
		protoKeywords: protoKeywords,
	}
	if err := r.updateRules(vlanID, rule); err != nil {
		return fmt.Errorf("failed to update Suricata rules for L7 rule %s of %s: %w", ruleID, policyName, err)
	}
	return nil
}

func (r *Reconciler) DeleteRule(ruleID string, vlanID uint32) error {
	start := time.Now()
	defer func() {
		klog.V(5).Infof("DeleteRule took %v", time.Since(start))
	}()

	if err := r.updateRules(vlanID, nil); err != nil {
		return fmt.Errorf("failed to update Suricata rules for L7 rule %s: %w", ruleID, err)
	}
	return nil
}

// updateRules sets the L7 rule owning the given VLAN ID, removing it when rule is nil, then rewrites
// the rules file and asks Suricata to reload it.
func (r *Reconciler) updateRules(vlanID uint32, rule *l7Rule) error {
	r.rulesMutex.Lock()
	if rule == nil {
		delete(r.rulesByVlanID, vlanID)
	} else {
		r.rulesByVlanID[vlanID] = rule
	}
	r.rulesChanged = true
	r.rulesMutex.Unlock()

	return r.syncRules()
}

// syncRules writes the rules file and reloads Suricata if the rules have changed since the last sync.
// It returns once a sync including every change made before the call has completed, whether this
// call performed it or a concurrent one did.
func (r *Reconciler) syncRules() error {
	r.syncMutex.Lock()
	defer r.syncMutex.Unlock()

	r.rulesMutex.Lock()
	if !r.rulesChanged {
		r.rulesMutex.Unlock()
		return nil
	}
	rulesData := r.buildRulesFileLocked()
	r.rulesChanged = false
	r.rulesMutex.Unlock()

	if err := r.writeAndReloadRules(rulesData); err != nil {
		// The file or the engine is behind the map, so the next sync must not be skipped.
		r.rulesMutex.Lock()
		r.rulesChanged = true
		r.rulesMutex.Unlock()
		return err
	}
	return nil
}

func (r *Reconciler) writeAndReloadRules(rulesData *bytes.Buffer) error {
	if err := writeConfigFile(rulesPath, rulesData); err != nil {
		return fmt.Errorf("failed to write Suricata rules file %s: %w", rulesPath, err)
	}
	resp, err := r.reloadSuricataRules()
	if err != nil {
		return err
	}
	if resp.Return != scCmdOK {
		return fmt.Errorf("failed to reload Suricata rules: %v", resp.Message)
	}
	klog.V(4).InfoS("Reloaded Suricata rules successfully", "ResponseMsg", resp.Message)
	return nil
}

// buildRulesFileLocked returns the content of the rules file.
//
// SIDs are handed out as the file is written, which is what keeps them unique. Deriving them from the
// VLAN ID instead would need a fixed number of SIDs per L7 rule, and an L7 rule with more criteria
// than that would take the SIDs of the next one. Suricata refuses a rules file holding a duplicate
// SID, so one such L7 rule would stop every L7 rule on the Node from being enforced.
//
// The VLAN IDs are sorted so that the same set of L7 rules always produces the same file, and so the
// same SIDs. They do change when an L7 rule is added or removed, which is why the policy a rejection
// belongs to is reported in its message rather than being looked up from its SID.
func (r *Reconciler) buildRulesFileLocked() *bytes.Buffer {
	vlanIDs := make([]uint32, 0, len(r.rulesByVlanID))
	for vlanID := range r.rulesByVlanID {
		vlanIDs = append(vlanIDs, vlanID)
	}
	sort.Slice(vlanIDs, func(i, j int) bool { return vlanIDs[i] < vlanIDs[j] })

	buf := bytes.NewBufferString(commonRulesData)
	sid := commonRulesSID + 1
	for _, vlanID := range vlanIDs {
		sid = writeRules(buf, r.rulesByVlanID[vlanID], sid)
	}
	return buf
}

func (r *Reconciler) reloadSuricataRules() (*scCmdRet, error) {
	return r.suricataScFn("ruleset-reload-rules")
}

func (r *Reconciler) startSuricata() error {
	f, err := defaultFS.Create(antreaSuricataConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create Suricata config file %s: %w", antreaSuricataConfigPath, err)
	}
	defer f.Close()
	if _, err = f.WriteString(suricataAntreaConfigData); err != nil {
		return fmt.Errorf("failed to write Suricata config file %s: %w", antreaSuricataConfigPath, err)
	}

	// Suricata fails to start when a configured rules file is missing, so create it before starting.
	if err = defaultFS.MkdirAll(rulesDir, 0755); err != nil {
		return fmt.Errorf("failed to create Suricata rules directory %s: %w", rulesDir, err)
	}
	if err = writeConfigFile(rulesPath, bytes.NewBufferString(commonRulesData)); err != nil {
		return fmt.Errorf("failed to write Suricata rules file %s: %w", rulesPath, err)
	}

	// Open the default Suricata config file /etc/suricata/suricata.yaml.
	f, err = defaultFS.OpenFile(defaultSuricataConfigPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open default Suricata config file %s: %w", defaultSuricataConfigPath, err)
	}
	defer f.Close()
	// Include the config file /etc/suricata/antrea.yaml for Antrea in the default Suricata config file /etc/suricata/suricata.yaml.
	if _, err = fmt.Fprintf(f, "include: %s\n", antreaSuricataConfigPath); err != nil {
		return fmt.Errorf("failed to update default Suricata config file %s: %w", defaultSuricataConfigPath, err)
	}

	r.startSuricataFn()

	// Wait Suricata command socket file to be ready.
	err = wait.PollUntilContextTimeout(context.TODO(), 100*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		if _, err = defaultFS.Stat(suricataCommandSocket); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to find Suricata command socket file: %w", err)
	}
	klog.InfoS("Started Suricata instance successfully")
	return nil
}

func startSuricata() {
	// Create log directory for Suricata. The rules directory is created by the caller, which writes the
	// rules file into it before Suricata is started.
	antreaSuricataLogPath := filepath.Join(logdir.GetLogDir(), antreaSuricataLogSubdir)
	if err := os.MkdirAll(antreaSuricataLogPath, 0755); err != nil {
		klog.ErrorS(err, "Failed to create L7 Network Policy log directory", "directory", antreaSuricataLogPath)
	}
	// Start Suricata with default Suricata config file /etc/suricata/suricata.yaml.
	cmd := exec.Command("suricata", "-c", defaultSuricataConfigPath, "--af-packet", "-D", "-l", antreaSuricataLogPath)
	if err := cmd.Run(); err != nil {
		klog.ErrorS(err, "Failed to start Suricata instance")
	}
}

func suricataSc(scCmd string) (*scCmdRet, error) {
	cmd := exec.Command("suricatasc", "-c", scCmd)
	retBytes, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run Suricata command '%s': %w", scCmd, err)
	}
	var ret scCmdRet
	if err = json.Unmarshal(retBytes, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}
