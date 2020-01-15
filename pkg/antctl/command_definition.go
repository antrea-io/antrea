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
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/fatih/structtag"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl/handlers"
)

type formatterType string

const (
	jsonFormatter  formatterType = "json"
	yamlFormatter  formatterType = "yaml"
	tableFormatter formatterType = "table"
)

// commandGroup is used to group commands, it could be specified in commandDefinition.
// The default commandGroup of a commandDefinition is `flat` which means the command
// is a direct sub-command of the root command. For any other commandGroup, the
// antctl framework will generate a same name sub-command of the root command for
// each of them, any commands specified as one of these group will need to be invoked
// as:
//   antctl <commandGroup> <command>
type commandGroup uint

const (
	flat commandGroup = iota
	get
)

var groupCommands = map[commandGroup]*cobra.Command{
	get: {
		Use:   "get",
		Short: "Get the status or resource of a topic",
		Long:  "Get the status or resource of a topic",
	},
}

const (
	// tagKey is the tag name of the antctl specific annotation.
	// For example:
	// 	type FooResponse struct {
	// 		Bar BarType `antctl:"key"`
	// 	}
	// If the field is annotated with antctl:"key", the framework assumes this field
	// could be used to retrieve a unique Response, thus the framework will generate
	// corresponding arg options to the cobra.Command.
	tagKey = "antctl"
	// tagOptionKeyArg is the option for antctl annotation. It tells the antctl
	// the field is a primary key.
	tagOptionKeyArg = "key"
)

// argOption describes one argument which can be used in a RequestOption.
type argOption struct {
	name      string
	fieldName string
	usage     string
	key       bool
}

// commandDefinition defines options to create a cobra.Command for an antctl client.
type commandDefinition struct {
	// Cobra related
	Use     string // The lower value of it will be used as the endpoint path, like: <API group>/<lower(Use)>.
	Short   string
	Long    string
	Example string // It will be filled with generated examples if it is not provided.
	// commandGroup represents the group of the command.
	CommandGroup commandGroup
	// Controller should be true if this command works for antrea-controller.
	Controller bool
	// Agent should be true if this command works for antrea-agent.
	Agent bool
	// SingleObject should be true if the handler always returns single object. The
	// antctl assumes the response data as a slice of the objects by default.
	SingleObject bool
	// API is the endpoint for the command to retrieve data.
	API string
	// The handler factory of the command.
	HandlerFactory handlers.Factory
	// GroupVersion is the group version of the command handler, it should be set
	// alongside with the HandlerFactory.
	GroupVersion *schema.GroupVersion
	// TransformedResponse is the final response struct of the command. If the
	// AddonTransform is set, TransformedResponse is not needed to be used as the
	// response struct of the handler, but it is still needed to guide the formatter.
	// It should always be filled.
	TransformedResponse reflect.Type
	// AddonTransform is used to transform or update the response data received
	// from the handler, it must returns an interface which has same type as
	// TransformedResponse.
	AddonTransform func(reader io.Reader, single bool) (interface{}, error)
}

// applySubCommandToRoot applies the commandDefinition to a cobra.Command with
// the client. It populates basic fields of a cobra.Command and creates the
// appropriate RunE function for it according to the commandDefinition.
func (cd *commandDefinition) applySubCommandToRoot(root *cobra.Command, client *client, isAgent bool) {
	cmd := &cobra.Command{
		Use:   cd.Use,
		Short: cd.Short,
		Long:  cd.Long,
	}
	renderDescription(cmd, isAgent)

	cd.applyFlagsToCommand(cmd)
	var keyArgOption *argOption
	argOpts := cd.argOptions()
	for i := range argOpts {
		a := argOpts[i]
		if a.key {
			cmd.Use += fmt.Sprintf(" [%s]", a.name)
			cmd.Long += "\n\nArgs:\n" + fmt.Sprintf("  %s\t%s", a.name, a.usage)
			// save the key arg option
			keyArgOption = a
		}
	}

	if groupCommand, ok := groupCommands[cd.CommandGroup]; ok {
		groupCommand.AddCommand(cmd)
	} else {
		root.AddCommand(cmd)
	}
	cd.applyExampleToCommand(cmd, keyArgOption)

	// Set key arg length validator to the command.
	if keyArgOption != nil {
		cmd.Args = cobra.MaximumNArgs(1)
	} else {
		cmd.Args = cobra.NoArgs
	}

	cmd.RunE = cd.newCommandRunE(keyArgOption, client)
}

// validate checks if the commandDefinition is valid.
func (cd *commandDefinition) validate() []error {
	var errs []error
	if len(cd.Use) == 0 {
		errs = append(errs, fmt.Errorf("the command does not have name"))
	}
	if cd.TransformedResponse == nil {
		errs = append(errs, fmt.Errorf("%s: command does not define output struct", cd.Use))
	}
	if !cd.Agent && !cd.Controller {
		errs = append(errs, fmt.Errorf("%s: command does not define any supported component", cd.Use))
	}
	if cd.HandlerFactory == nil && len(cd.API) == 0 {
		errs = append(errs, fmt.Errorf("%s: no handler or API specified", cd.Use))
	}
	if len(cd.API) != 0 && cd.Agent {
		errs = append(errs, fmt.Errorf("%s: commands for agent do not allow to request API directly", cd.Use))
	}
	if cd.HandlerFactory != nil && cd.GroupVersion == nil {
		errs = append(errs, fmt.Errorf("%s: must provide the group version of customize handler", cd.Use))
	}
	// Only one key arg is allowed.
	var hasKey bool
	for _, arg := range cd.argOptions() {
		if arg.key && hasKey {
			errs = append(errs, fmt.Errorf("%s: has more than one key field", cd.Use))
			break
		} else if arg.key {
			hasKey = true
		}
	}
	return errs
}

// argOptions returns the list of arguments that could be used in a commandDefinition.
func (cd *commandDefinition) argOptions() []*argOption {
	var ret []*argOption
	for i := 0; i < cd.TransformedResponse.NumField(); i++ {
		f := cd.TransformedResponse.Field(i)
		argOpt := &argOption{fieldName: f.Name}

		tags, err := structtag.Parse(string(f.Tag))
		if err != nil { // Broken cli tags, skip this field
			continue
		}

		jsonTag, err := tags.Get("json")
		if err != nil {
			argOpt.name = strings.ToLower(f.Name)
		} else {
			argOpt.name = jsonTag.Name
		}

		cliTag, err := tags.Get(tagKey)
		if err == nil {
			argOpt.key = cliTag.Name == tagOptionKeyArg
			argOpt.usage = strings.Join(cliTag.Options, ", ")
		}

		ret = append(ret, argOpt)
	}
	return ret
}

// decode parses the data in reader and converts it to one or more
// TransformedResponse objects. If single is false, the return type is
// []TransformedResponse. Otherwise, the return type is TransformedResponse.
func (cd *commandDefinition) decode(r io.Reader, single bool) (interface{}, error) {
	var result interface{}

	if single || cd.SingleObject {
		ref := reflect.New(cd.TransformedResponse)
		err := json.NewDecoder(r).Decode(ref.Interface())
		if err != nil {
			return nil, err
		}
		result = ref.Interface()
	} else {
		ref := reflect.New(reflect.SliceOf(cd.TransformedResponse))
		err := json.NewDecoder(r).Decode(ref.Interface())
		if err != nil {
			return nil, err
		}
		result = reflect.Indirect(ref).Interface()
	}

	return result, nil
}

func (cd *commandDefinition) jsonOutput(obj interface{}, writer io.Writer) error {
	var output bytes.Buffer
	err := json.NewEncoder(&output).Encode(obj)
	if err != nil {
		return fmt.Errorf("error when encoding data in json: %w", err)
	}
	var prettifiedBuf bytes.Buffer
	err = json.Indent(&prettifiedBuf, output.Bytes(), "", "  ")
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
	err := yaml.NewEncoder(writer).Encode(obj)
	if err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	return nil
}

// output reads bytes from the resp and outputs the data to the writer in desired
// format. If the AddonTransform is set, it will use the function to transform
// the data first. It will try to output the resp in the format ft specified after
// doing transform.
func (cd *commandDefinition) output(resp io.Reader, writer io.Writer, ft formatterType, single bool) (err error) {
	var obj interface{}
	if cd.AddonTransform == nil { // Decode the data if there is no AddonTransform.
		obj, err = cd.decode(resp, single)
		if err != nil {
			return fmt.Errorf("error when decoding response: %w", err)
		}
	} else {
		obj, err = cd.AddonTransform(resp, single)
		if err != nil {
			return fmt.Errorf("error when doing local transform: %w", err)
		}
		klog.Infof("After transforming %v", obj)
	}

	// Output structure data in format
	switch ft {
	case jsonFormatter:
		return cd.jsonOutput(obj, writer)
	case yamlFormatter:
		return cd.yamlOutput(obj, writer)
	case tableFormatter: // TODO: Add table formatter
		panic("Implement it")
	default:
		return fmt.Errorf("unsupport format type: %v", ft)
	}
}

// newCommandRunE creates the RunE function for the command. The RunE function
// checks the args according to ArgOptions and flags.
func (cd *commandDefinition) newCommandRunE(key *argOption, c *client) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		argMap := make(map[string]string)
		if len(args) > 0 {
			argMap[key.name] = args[0]
		}
		kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		var reqPath string
		if len(cd.API) > 0 {
			reqPath = cd.API
		} else {
			reqPath = "/apis/" + cd.GroupVersion.String() + "/" + strings.ToLower(cd.Use)
		}
		resp, err := c.Request(&RequestOption{
			Path:         reqPath,
			Kubeconfig:   kubeconfigPath,
			Name:         cmd.Name(),
			Args:         argMap,
			TimeOut:      timeout,
			GroupVersion: cd.GroupVersion,
		})
		if err != nil {
			return err
		}
		single := len(argMap) != 0
		outputFormat, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		return cd.output(resp, os.Stdout, formatterType(outputFormat), single)
	}
}

// applyFlagsToCommand sets up flags for the command.
func (cd *commandDefinition) applyFlagsToCommand(cmd *cobra.Command) {
	cmd.Flags().StringP("output", "o", "json", "output format: json|yaml|table")
}

func (cd *commandDefinition) requestPath(prefix string) string {
	return path.Join(prefix, strings.ToLower(cd.Use))
}

// applyExampleToCommand generates examples according to the commandDefinition.
// It only creates for commands which specified TransformedResponse. If the SingleObject
// is specified, it only creates one example to retrieve the single object. Otherwise,
// it will generates examples about retrieving single object according to the key
// argOption and retrieving the object list.
func (cd *commandDefinition) applyExampleToCommand(cmd *cobra.Command, key *argOption) {
	if len(cd.Example) != 0 {
		cmd.Example = cd.Example
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
	typeName := cd.TransformedResponse.Name()
	dataName := strings.ToLower(strings.TrimSuffix(typeName, "Response"))

	if cd.SingleObject {
		fmt.Fprintf(&buf, "  Get the %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(commands, " "))
	} else {
		if key != nil {
			fmt.Fprintf(&buf, "  Get a %s\n", dataName)
			fmt.Fprintf(&buf, "  $ %s [%s]\n", strings.Join(commands, " "), key.name)
		}
		fmt.Fprintf(&buf, "  Get the list of %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(commands, " "))
	}

	cmd.Example = buf.String()
}
