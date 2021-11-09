// Copyright 2019 Antrea Authors
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

package antctl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/antctl/transform/common"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/controller/networkpolicy"
)

type formatterType string

const (
	jsonFormatter  formatterType = "json"
	yamlFormatter  formatterType = "yaml"
	tableFormatter formatterType = "table"
)

const (
	maxTableOutputColumnLength int    = 50
	sortByEffectivePriority    string = "effectivePriority"
)

// commandGroup is used to group commands, it could be specified in commandDefinition.
// The default commandGroup of a commandDefinition is `flat` which means the command
// is a direct sub-command of the root command. For any other commandGroup, the
// antctl framework will generate a same name sub-command of the root command for
// each of them, any commands specified as one of these group will need to be invoked
// as:
//   antctl <commandGroup> <command>
type commandGroup uint
type OutputType uint

// There are two output types: single item or list and the actual type is decided by
// OutputType value here and command's arguments.
const (
	// defaultType represents the output type is single item if there is an argument
	// and its value is provided. If not, the output type is list.
	defaultType OutputType = iota
	// single represents the output type is always single item.
	single
	// multiple represents the output type is always list.
	multiple
)

const (
	flat commandGroup = iota
	get
	query
)

var groupCommands = map[commandGroup]*cobra.Command{
	get: {
		Use:   "get",
		Short: "Get the status or resource of a topic",
		Long:  "Get the status or resource of a topic",
	},
	query: {
		Use:   "query",
		Short: "Execute a user-provided query",
		Long:  "Execute a user-provided query",
	},
}

type endpointResponder interface {
	OutputType() OutputType
	flags() []flagInfo
}

type resourceEndpoint struct {
	groupVersionResource *schema.GroupVersionResource
	resourceName         string
	namespaced           bool
}

func (e *resourceEndpoint) OutputType() OutputType {
	if len(e.resourceName) != 0 {
		return single
	}
	return defaultType
}

func (e *resourceEndpoint) flags() []flagInfo {
	var flags []flagInfo
	if len(e.resourceName) == 0 {
		flags = append(flags, flagInfo{
			name:         "name",
			defaultValue: "",
			arg:          true,
			usage:        "Retrieve the resource by name",
		})
	}
	if e.namespaced {
		flags = append(flags, flagInfo{
			name:         "namespace",
			shorthand:    "n",
			defaultValue: metav1.NamespaceAll,
			usage:        "Filter the resource by namespace",
		})
	}
	if e.groupVersionResource == &v1beta2.NetworkPolicyVersionResource {
		flags = append(flags, getSortByFlag())
	}
	return flags
}

func getSortByFlag() flagInfo {
	return flagInfo{
		name:            "sort-by",
		defaultValue:    "",
		supportedValues: []string{sortByEffectivePriority},
		usage:           "Get NetworkPolicies in specific order. Current supported value is effectivePriority.",
	}
}

type nonResourceEndpoint struct {
	path       string
	params     []flagInfo
	outputType OutputType
}

func (e *nonResourceEndpoint) flags() []flagInfo {
	return e.params
}

func (e *nonResourceEndpoint) OutputType() OutputType {
	return e.outputType
}

// endpoint is used to specified the API for an antctl running against antrea-controller.
type endpoint struct {
	resourceEndpoint    *resourceEndpoint
	nonResourceEndpoint *nonResourceEndpoint
	// addonTransform is used to transform or update the response data received
	// from the handler, it must returns an interface which has same type as
	// TransformedResponse.
	addonTransform func(reader io.Reader, single bool, opts map[string]string) (interface{}, error)
	// requestErrorFallback is called when a client request fails, in which
	// case transforms are called on the io.Reader object returned by this
	// function. This is useful if a command still needs to output useful
	// information in case of error.
	requestErrorFallback func() (io.Reader, error)
}

// flagInfo represents a command-line flag that can be provided when invoking an antctl command.
type flagInfo struct {
	name            string
	shorthand       string
	defaultValue    string
	supportedValues []string
	arg             bool
	usage           string
}

// rawCommand defines a full function cobra.Command which lets developers
// write complex client-side tasks. Only the global flags of the antctl framework will
// be passed to the cobra.Command.
type rawCommand struct {
	cobraCommand      *cobra.Command
	supportAgent      bool
	supportController bool
	commandGroup      commandGroup
}

// commandDefinition defines options to create a cobra.Command for an antctl client.
type commandDefinition struct {
	// Cobra related
	use     string
	aliases []string
	short   string
	long    string
	example string // It will be filled with generated examples if it is not provided.
	// commandGroup represents the group of the command.
	commandGroup           commandGroup
	controllerEndpoint     *endpoint
	agentEndpoint          *endpoint
	flowAggregatorEndpoint *endpoint
	// transformedResponse is the final response struct of the command. If the
	// AddonTransform is set, TransformedResponse is not needed to be used as the
	// response struct of the handler, but it is still needed to guide the formatter.
	// It should always be filled.
	transformedResponse reflect.Type
}

func (cd *commandDefinition) namespaced() bool {
	if runtime.Mode == runtime.ModeAgent {
		return cd.agentEndpoint != nil && cd.agentEndpoint.resourceEndpoint != nil && cd.agentEndpoint.resourceEndpoint.namespaced
	} else if runtime.Mode == runtime.ModeController {
		return cd.controllerEndpoint != nil && cd.controllerEndpoint.resourceEndpoint != nil && cd.controllerEndpoint.resourceEndpoint.namespaced
	} else if runtime.Mode == runtime.ModeFlowAggregator {
		return cd.flowAggregatorEndpoint != nil && cd.flowAggregatorEndpoint.resourceEndpoint != nil && cd.flowAggregatorEndpoint.resourceEndpoint.namespaced
	}
	return false
}

func (cd *commandDefinition) getAddonTransform() func(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	if runtime.Mode == runtime.ModeAgent && cd.agentEndpoint != nil {
		return cd.agentEndpoint.addonTransform
	} else if runtime.Mode == runtime.ModeController && cd.controllerEndpoint != nil {
		return cd.controllerEndpoint.addonTransform
	} else if runtime.Mode == runtime.ModeFlowAggregator && cd.flowAggregatorEndpoint != nil {
		return cd.flowAggregatorEndpoint.addonTransform
	}
	return nil
}

func (cd *commandDefinition) getEndpoint() endpointResponder {
	if runtime.Mode == runtime.ModeAgent {
		if cd.agentEndpoint != nil {
			if cd.agentEndpoint.resourceEndpoint != nil {
				return cd.agentEndpoint.resourceEndpoint
			}
			return cd.agentEndpoint.nonResourceEndpoint
		}
	} else if runtime.Mode == runtime.ModeController {
		if cd.controllerEndpoint != nil {
			if cd.controllerEndpoint.resourceEndpoint != nil {
				return cd.controllerEndpoint.resourceEndpoint
			}
			return cd.controllerEndpoint.nonResourceEndpoint
		}
	} else if runtime.Mode == runtime.ModeFlowAggregator {
		if cd.flowAggregatorEndpoint != nil {
			if cd.flowAggregatorEndpoint.resourceEndpoint != nil {
				return cd.flowAggregatorEndpoint.resourceEndpoint
			}
			return cd.flowAggregatorEndpoint.nonResourceEndpoint
		}
	}
	return nil
}

func (cd *commandDefinition) getRequestErrorFallback() func() (io.Reader, error) {
	if runtime.Mode == runtime.ModeAgent {
		if cd.agentEndpoint != nil {
			return cd.agentEndpoint.requestErrorFallback
		}
	} else if runtime.Mode == runtime.ModeController {
		if cd.controllerEndpoint != nil {
			return cd.controllerEndpoint.requestErrorFallback
		}
	} else if runtime.Mode == runtime.ModeFlowAggregator {
		if cd.flowAggregatorEndpoint != nil {
			return cd.flowAggregatorEndpoint.requestErrorFallback
		}
	}
	return nil
}

// applySubCommandToRoot applies the commandDefinition to a cobra.Command with
// the client. It populates basic fields of a cobra.Command and creates the
// appropriate RunE function for it according to the commandDefinition.
func (cd *commandDefinition) applySubCommandToRoot(root *cobra.Command, client AntctlClient, out io.Writer) {
	cmd := &cobra.Command{
		Use:     cd.use,
		Aliases: cd.aliases,
		Short:   cd.short,
		Long:    cd.long,
	}
	renderDescription(cmd)
	cd.applyFlagsToCommand(cmd)

	if groupCommand, ok := groupCommands[cd.commandGroup]; ok {
		groupCommand.AddCommand(cmd)
	} else {
		root.AddCommand(cmd)
	}
	cd.applyExampleToCommand(cmd)

	cmd.RunE = cd.newCommandRunE(client, out)
}

// validate checks if the commandDefinition is valid.
func (cd *commandDefinition) validate() []error {
	var errs []error
	if len(cd.use) == 0 {
		errs = append(errs, fmt.Errorf("the command does not have name"))
	}
	existingAliases := make(map[string]bool)
	for _, a := range cd.aliases {
		if a == cd.use {
			errs = append(errs, fmt.Errorf("%s: command alias is the same with use of the command", cd.use))
		}
		if _, ok := existingAliases[a]; ok {
			errs = append(errs, fmt.Errorf("%s: command alias is provided twice: %s", cd.use, a))
		}
		existingAliases[a] = true
	}
	if cd.transformedResponse == nil {
		errs = append(errs, fmt.Errorf("%s: command does not define output struct", cd.use))
	}
	if cd.agentEndpoint == nil && cd.controllerEndpoint == nil && cd.flowAggregatorEndpoint == nil {
		errs = append(errs, fmt.Errorf("%s: command does not define any supported component", cd.use))
	}
	if cd.agentEndpoint != nil && cd.agentEndpoint.nonResourceEndpoint != nil && cd.agentEndpoint.resourceEndpoint != nil {
		errs = append(errs, fmt.Errorf("%s: command for agent can only define one endpoint", cd.use))
	}
	if cd.agentEndpoint != nil && cd.agentEndpoint.nonResourceEndpoint == nil && cd.agentEndpoint.resourceEndpoint == nil {
		errs = append(errs, fmt.Errorf("%s: command for agent must define one endpoint", cd.use))
	}
	if cd.controllerEndpoint != nil && cd.controllerEndpoint.nonResourceEndpoint != nil && cd.controllerEndpoint.resourceEndpoint != nil {
		errs = append(errs, fmt.Errorf("%s: command for controller can only define one endpoint", cd.use))
	}
	if cd.controllerEndpoint != nil && cd.controllerEndpoint.nonResourceEndpoint == nil && cd.controllerEndpoint.resourceEndpoint == nil {
		errs = append(errs, fmt.Errorf("%s: command for controller must define one endpoint", cd.use))
	}
	if cd.flowAggregatorEndpoint != nil && cd.flowAggregatorEndpoint.nonResourceEndpoint != nil && cd.flowAggregatorEndpoint.resourceEndpoint != nil {
		errs = append(errs, fmt.Errorf("%s: command for flow aggregator can only define one endpoint", cd.use))
	}
	if cd.flowAggregatorEndpoint != nil && cd.flowAggregatorEndpoint.nonResourceEndpoint == nil && cd.flowAggregatorEndpoint.resourceEndpoint == nil {
		errs = append(errs, fmt.Errorf("%s: command for flow aggregator must define one endpoint", cd.use))
	}
	empty := struct{}{}
	existingFlags := map[string]struct{}{"output": empty, "help": empty, "kubeconfig": empty, "timeout": empty, "verbose": empty}
	if endpoint := cd.getEndpoint(); endpoint != nil {
		for _, f := range endpoint.flags() {
			if len(f.name) == 0 {
				errs = append(errs, fmt.Errorf("%s: flag name cannot be empty", cd.use))
			} else {
				if _, ok := existingFlags[f.name]; ok {
					errs = append(errs, fmt.Errorf("%s: flag redefined: %s", cd.use, f.name))
				}
				existingFlags[f.name] = empty
			}
			if len(f.shorthand) > 1 {
				errs = append(errs, fmt.Errorf("%s: length of a flag shorthand cannot be larger than 1: %s", cd.use, f.shorthand))
			}
		}
	}
	return errs
}

// decode parses the data in reader and converts it to one or more
// TransformedResponse objects. If single is false, the return type is
// []TransformedResponse. Otherwise, the return type is TransformedResponse.
func (cd *commandDefinition) decode(r io.Reader, single bool) (interface{}, error) {
	var refType reflect.Type
	if single {
		refType = cd.transformedResponse
	} else {
		refType = reflect.SliceOf(cd.transformedResponse)
	}
	ref := reflect.New(refType)
	err := json.NewDecoder(r).Decode(ref.Interface())
	if err != nil {
		return nil, err
	}
	if single {
		return ref.Interface(), nil
	}
	return reflect.Indirect(ref).Interface(), nil
}

func jsonEncode(obj interface{}, output *bytes.Buffer) error {
	if err := json.NewEncoder(output).Encode(obj); err != nil {
		return fmt.Errorf("error when encoding data in json: %w", err)
	}
	return nil
}

func (cd *commandDefinition) jsonOutput(obj interface{}, writer io.Writer) error {
	var output bytes.Buffer
	if err := jsonEncode(obj, &output); err != nil {
		return fmt.Errorf("error when encoding data in json: %w", err)
	}

	var prettifiedBuf bytes.Buffer
	err := json.Indent(&prettifiedBuf, output.Bytes(), "", "  ")
	if err != nil {
		return fmt.Errorf("error when formatting outputing in json: %w", err)
	}
	_, err = io.Copy(writer, &prettifiedBuf)
	if err != nil {
		return fmt.Errorf("error when outputing in json format: %w", err)
	}
	return nil
}

func (cd *commandDefinition) yamlOutput(obj interface{}, writer io.Writer) error {
	var jsonObj interface{}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(obj); err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	// Comment copied from: sigs.k8s.io/yaml
	// We are using yaml.Unmarshal here (instead of json.Unmarshal) because the
	// Go JSON library doesn't try to pick the right number type (int, float,
	// etc.) when unmarshalling to interface{}, it just picks float64
	// universally. go-yaml does go through the effort of picking the right
	// number type, so we can preserve number type throughout this process.
	if err := yaml.Unmarshal(buf.Bytes(), &jsonObj); err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	if err := yaml.NewEncoder(writer).Encode(jsonObj); err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	return nil
}

// respTransformer collects output fields in original transformedResponse
// and flattens them. respTransformer realizes this by turning obj into
// JSON and unmarshalling it.
// E.g. agent's transformedVersionResponse will only have two fields after
// transforming: agentVersion and antctlVersion.
func respTransformer(obj interface{}) (interface{}, error) {
	var jsonObj bytes.Buffer
	if err := json.NewEncoder(&jsonObj).Encode(obj); err != nil {
		return nil, fmt.Errorf("error when encoding data in json: %w", err)
	}
	jsonStr := jsonObj.String()

	var target interface{}
	if err := json.Unmarshal([]byte(jsonStr), &target); err != nil {
		return nil, fmt.Errorf("error when unmarshalling data in json: %w", err)
	}
	return target, nil
}

// tableOutputForGetCommands formats the table output for "get" commands.
func (cd *commandDefinition) tableOutputForGetCommands(obj interface{}, writer io.Writer) error {
	var list []common.TableOutput
	if reflect.TypeOf(obj).Kind() == reflect.Slice {
		s := reflect.ValueOf(obj)
		if s.Len() == 0 || s.Index(0).Interface() == nil {
			var buffer bytes.Buffer
			buffer.WriteString("\n")
			if _, err := io.Copy(writer, &buffer); err != nil {
				return fmt.Errorf("error when copy output into writer: %w", err)
			}
			return nil
		}
		if _, ok := s.Index(0).Interface().(common.TableOutput); !ok {
			return cd.tableOutput(obj, writer)
		}
		for i := 0; i < s.Len(); i++ {
			ele := s.Index(i)
			list = append(list, ele.Interface().(common.TableOutput))
		}
	} else {
		ele, ok := obj.(common.TableOutput)
		if !ok {
			return cd.tableOutput(obj, writer)
		}
		list = []common.TableOutput{ele}
	}

	// Get the elements and headers of table.
	args := list[0].GetTableHeader()
	rows := make([][]string, len(list)+1)
	rows[0] = list[0].GetTableHeader()
	for i, element := range list {
		rows[i+1] = element.GetTableRow(maxTableOutputColumnLength)
	}

	if list[0].SortRows() {
		// Sort the table rows according to columns in order.
		body := rows[1:]
		sort.Slice(body, func(i, j int) bool {
			for k := range body[i] {
				if body[i][k] != body[j][k] {
					return body[i][k] < body[j][k]
				}
			}
			return true
		})
	}
	// Construct the table.
	numRows, numCols := len(list)+1, len(args)
	widths := getColumnWidths(numRows, numCols, rows)
	return constructTable(numRows, numCols, widths, rows, writer)
}

func getColumnWidths(numRows int, numCols int, rows [][]string) []int {
	widths := make([]int, numCols)
	if numCols == 1 {
		// Do not limit the column length for a single column table.
		// This is for the case a single column table can have long rows which cannot
		// fit into a single line (one example is the ovsflows outputs).
		widths[0] = 0
	} else {
		// Get the width of every column.
		for j := 0; j < numCols; j++ {
			width := len(rows[0][j])
			for i := 1; i < numRows; i++ {
				if len(rows[i][j]) == 0 {
					rows[i][j] = "<NONE>"
				}
				if width < len(rows[i][j]) {
					width = len(rows[i][j])
				}
			}
			widths[j] = width
			if j != 0 {
				widths[j]++
			}
		}
	}
	return widths
}

func constructTable(numRows int, numCols int, widths []int, rows [][]string, writer io.Writer) error {
	var buffer bytes.Buffer
	for i := 0; i < numRows; i++ {
		for j := 0; j < numCols; j++ {
			val := ""
			if j != 0 {
				val = " " + val
			}
			val += rows[i][j]
			if widths[j] > 0 {
				val += strings.Repeat(" ", widths[j]-len(val))
			}
			buffer.WriteString(val)
		}
		buffer.WriteString("\n")
	}
	if _, err := io.Copy(writer, &buffer); err != nil {
		return fmt.Errorf("error when copy output into writer: %w", err)
	}

	return nil
}

// tableOutputForQueryEndpoint implements printing sub tables (list of tables) for each response, utilizing constructTable
// with multiplicity.
func (cd *commandDefinition) tableOutputForQueryEndpoint(obj interface{}, writer io.Writer) error {
	// intermittent new line buffer
	var buffer bytes.Buffer
	newLine := func() error {
		buffer.WriteString("\n")
		if _, err := io.Copy(writer, &buffer); err != nil {
			return fmt.Errorf("error when copy output into writer: %w", err)
		}
		buffer.Reset()
		return nil
	}
	// sort rows of sub table
	sortRows := func(rows [][]string) {
		body := rows[1:]
		sort.Slice(body, func(i, j int) bool {
			for k := range body[i] {
				if body[i][k] != body[j][k] {
					return body[i][k] < body[j][k]
				}
			}
			return true
		})
	}
	// constructs sub tables for responses
	constructSubTable := func(header [][]string, body [][]string) error {
		rows := append(header, body...)
		sortRows(rows)
		numRows, numCol := len(rows), len(rows[0])
		widths := getColumnWidths(numRows, numCol, rows)
		if err := constructTable(numRows, numCol, widths, rows, writer); err != nil {
			return err
		}
		return nil
	}
	// construct sections of sub tables for responses (applied, ingress, egress)
	constructSection := func(label [][]string, header [][]string, body [][]string, nonEmpty bool) error {
		if err := constructSubTable(label, [][]string{}); err != nil {
			return err
		}
		if nonEmpty {
			if err := constructSubTable(header, body); err != nil {
				return err
			}
		}
		if err := newLine(); err != nil {
			return err
		}
		return nil
	}
	// iterate through each endpoint and construct response
	endpointQueryResponse := obj.(*networkpolicy.EndpointQueryResponse)
	for _, endpoint := range endpointQueryResponse.Endpoints {
		// transform applied policies to string representation
		policies := make([][]string, 0)
		for _, policy := range endpoint.Policies {
			policyStr := []string{policy.Name, policy.Namespace, string(policy.UID)}
			policies = append(policies, policyStr)
		}
		// transform egress and ingress rules to string representation
		egress, ingress := make([][]string, 0), make([][]string, 0)
		for _, rule := range endpoint.Rules {
			ruleStr := []string{rule.Name, rule.Namespace, strconv.Itoa(rule.RuleIndex), string(rule.UID)}
			if rule.Direction == v1beta2.DirectionIn {
				ingress = append(ingress, ruleStr)
			} else if rule.Direction == v1beta2.DirectionOut {
				egress = append(egress, ruleStr)
			}
		}
		// table label
		if err := constructSubTable([][]string{{"Endpoint " + endpoint.Namespace + "/" + endpoint.Name}}, [][]string{}); err != nil {
			return err
		}
		// applied policies
		nonEmpty := len(policies) > 0
		policyLabel := []string{"Applied Policies: None"}
		if nonEmpty {
			policyLabel = []string{"Applied Policies:"}
		}
		if err := constructSection([][]string{policyLabel}, [][]string{{"Name", "Namespace", "UID"}}, policies, nonEmpty); err != nil {
			return err
		}
		// egress rules
		nonEmpty = len(egress) > 0
		egressLabel := []string{"Egress Rules: None"}
		if nonEmpty {
			egressLabel = []string{"Egress Rules:"}
		}
		if err := constructSection([][]string{egressLabel}, [][]string{{"Name", "Namespace", "Index", "UID"}}, egress, nonEmpty); err != nil {
			return err
		}
		// ingress rules
		nonEmpty = len(ingress) > 0
		ingressLabel := []string{"Ingress Rules: None"}
		if nonEmpty {
			ingressLabel = []string{"Ingress Rules:"}
		}
		if err := constructSection([][]string{ingressLabel}, [][]string{{"Name", "Namespace", "Index", "UID"}}, ingress, nonEmpty); err != nil {
			return err
		}
	}
	return nil
}

func (cd *commandDefinition) tableOutput(obj interface{}, writer io.Writer) error {
	target, err := respTransformer(obj)
	if err != nil {
		return fmt.Errorf("error when transforming obj: %w", err)
	}

	list, multiple := target.([]interface{})
	var args []string
	if multiple {
		for _, el := range list {
			m := el.(map[string]interface{})
			for k := range m {
				args = append(args, k)
			}
			// break after one iteration intentionally (we are just retrieving attribute
			// names to use as the table header in the output)
			break // nolint:staticcheck
		}
	} else {
		m, _ := target.(map[string]interface{})
		for k := range m {
			args = append(args, k)
		}
	}

	var buffer bytes.Buffer
	for _, arg := range args {
		buffer.WriteString(arg)
		buffer.WriteString("\t")
	}
	attrLine := buffer.String()

	var valLines []string
	if multiple {
		for _, el := range list {
			m := el.(map[string]interface{})
			buffer.Reset()
			for _, k := range args {
				var output bytes.Buffer
				if err = jsonEncode(m[k], &output); err != nil {
					return fmt.Errorf("error when encoding data in json: %w", err)
				}
				buffer.WriteString(strings.Trim(output.String(), "\"\n"))
				buffer.WriteString("\t")
			}
			valLines = append(valLines, buffer.String())
		}
	} else {
		buffer.Reset()
		m, _ := target.(map[string]interface{})
		for _, k := range args {
			var output bytes.Buffer
			if err = jsonEncode(m[k], &output); err != nil {
				return fmt.Errorf("error when encoding: %w", err)
			}
			buffer.WriteString(strings.Trim(output.String(), "\"\n"))
			buffer.WriteString("\t")
		}
		valLines = append(valLines, buffer.String())
	}

	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 15, 0, 1, ' ', 0)
	fmt.Fprintln(w, attrLine)
	for _, line := range valLines {
		fmt.Fprintln(w, line)
	}
	w.Flush()

	if _, err = io.Copy(writer, &b); err != nil {
		return fmt.Errorf("error when copy output into writer: %w", err)
	}

	return nil
}

// output reads bytes from the resp and outputs the data to the writer in desired
// format. If the AddonTransform is set, it will use the function to transform
// the data first. It will try to output the resp in the format ft specified after
// doing transform.
func (cd *commandDefinition) output(resp io.Reader, writer io.Writer, ft formatterType, single bool, args map[string]string) (err error) {
	var obj interface{}
	addonTransform := cd.getAddonTransform()

	if addonTransform == nil { // Decode the data if there is no AddonTransform.
		obj, err = cd.decode(resp, single)
		if err == io.EOF {
			// No response returned.
			return nil
		}
		if err != nil {
			return fmt.Errorf("error when decoding response %v: %w", resp, err)
		}
	} else {
		obj, err = addonTransform(resp, single, args)
		if err != nil {
			return fmt.Errorf("error when doing local transform: %w", err)
		}
		klog.Infof("After transforming %v", obj)
	}

	if str, ok := obj.([]byte); ok {
		// If the transformed response is of type []byte, just output
		// the raw bytes.
		_, err = writer.Write(str)
		return err
	}

	// Output structure data in format
	switch ft {
	case jsonFormatter:
		return cd.jsonOutput(obj, writer)
	case yamlFormatter:
		return cd.yamlOutput(obj, writer)
	case tableFormatter:
		if cd.commandGroup == get {
			return cd.tableOutputForGetCommands(obj, writer)
		} else if cd.commandGroup == query {
			if cd.controllerEndpoint.nonResourceEndpoint.path == "/endpoint" {
				return cd.tableOutputForQueryEndpoint(obj, writer)
			}
		} else {
			return cd.tableOutput(obj, writer)
		}
	default:
		return fmt.Errorf("unsupported format type: %v", ft)
	}
	return nil
}

func (cd *commandDefinition) collectFlags(cmd *cobra.Command, args []string) (map[string]string, error) {
	argMap := make(map[string]string)
	if endpoint := cd.getEndpoint(); endpoint != nil {
		for _, f := range endpoint.flags() {
			if f.arg {
				if len(args) > 0 {
					argMap[f.name] = args[0]
				}
			} else {
				vs, err := cmd.Flags().GetString(f.name)
				if err == nil && len(vs) != 0 {
					if f.supportedValues != nil && !cd.validateFlagValue(vs, f.supportedValues) {
						return nil, fmt.Errorf("unsupported value %s for flag %s", vs, f.name)
					}
					argMap[f.name] = vs
					continue
				}
			}
		}
	}
	if cd.namespaced() {
		argMap["namespace"], _ = cmd.Flags().GetString("namespace")
	}
	return argMap, nil
}

func (cd *commandDefinition) validateFlagValue(val string, supportedValues []string) bool {
	for _, s := range supportedValues {
		if s == val {
			return true
		}
	}
	return false
}

// newCommandRunE creates the RunE function for the command. The RunE function
// checks the args according to argOption and flags.
func (cd *commandDefinition) newCommandRunE(c AntctlClient, out io.Writer) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		argMap, err := cd.collectFlags(cmd, args)
		if err != nil {
			return err
		}
		klog.Infof("Args: %v", argMap)
		var argGet bool
		for _, flag := range cd.getEndpoint().flags() {
			if _, ok := argMap[flag.name]; ok && flag.arg == true {
				argGet = true
				break
			}
		}
		kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		server, _ := cmd.Flags().GetString("server")
		outputFormat, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}

		resp, requestErr := c.request(&requestOption{
			commandDefinition: cd,
			kubeconfig:        kubeconfigPath,
			args:              argMap,
			timeout:           timeout,
			server:            server,
		})
		if requestErr != nil {
			fallback := cd.getRequestErrorFallback()
			if fallback == nil {
				return requestErr
			}
			resp, err = fallback()
			if err != nil {
				return err
			}
		}
		isSingle := cd.getEndpoint().OutputType() != multiple && (cd.getEndpoint().OutputType() == single || argGet)
		if err := cd.output(resp, out, formatterType(outputFormat), isSingle, argMap); err != nil {
			return err
		}
		return requestErr
	}
}

// applyFlagsToCommand sets up args and flags for the command.
func (cd *commandDefinition) applyFlagsToCommand(cmd *cobra.Command) {
	var hasFlag bool
	for _, flag := range cd.getEndpoint().flags() {
		if flag.arg {
			cmd.Args = cobra.MaximumNArgs(1)
			cmd.Use += fmt.Sprintf(" [%s]", flag.name)
			cmd.Long += fmt.Sprintf("\n\nArgs:\n  %s\t%s", flag.name, flag.usage)
			hasFlag = true
		} else {
			cmd.Flags().StringP(flag.name, flag.shorthand, flag.defaultValue, flag.usage)
		}
	}
	if !hasFlag {
		cmd.Args = cobra.NoArgs
	}
	if cd.commandGroup == get {
		cmd.Flags().StringP("output", "o", "table", "output format: json|table|yaml")
	} else if cd.commandGroup == query {
		cmd.Flags().StringP("output", "o", "table", "output format: json|table|yaml")
	} else {
		cmd.Flags().StringP("output", "o", "yaml", "output format: json|table|yaml")
	}
}

// applyExampleToCommand generates examples according to the commandDefinition.
// It only creates for commands which specified TransformedResponse. If the singleObject
// is specified, it only creates one example to retrieve the single object. Otherwise,
// it will generates examples about retrieving single object according to the key
// argOption and retrieving the object list.
func (cd *commandDefinition) applyExampleToCommand(cmd *cobra.Command) {
	if len(cd.example) != 0 {
		cmd.Example = cd.example
		return
	}
	var commands []string
	for iter := cmd; iter != nil; iter = iter.Parent() {
		commands = append(commands, iter.Name())
	}
	for i := 0; i < len(commands)/2; i++ {
		commands[i], commands[len(commands)-1-i] = commands[len(commands)-1-i], commands[i]
	}

	var buf bytes.Buffer
	dataName := strings.ToLower(cd.use)

	if cd.getEndpoint().OutputType() == single {
		fmt.Fprintf(&buf, "  Get the %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(commands, " "))
	} else {
		fmt.Fprintf(&buf, "  Get a %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s [name]\n", strings.Join(commands, " "))
		fmt.Fprintf(&buf, "  Get the list of %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(commands, " "))
	}

	cmd.Example = buf.String()
}
