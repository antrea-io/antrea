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
	"reflect"
	"strings"
	"time"

	"github.com/fatih/structtag"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/vmware-tanzu/antrea/pkg/antctl/handlers"
)

type commandGroup uint

const (
	flat commandGroup = iota
	get
)

var groups = map[commandGroup]*cobra.Command{}

// Command returns the string representation of the command group.
func (g commandGroup) String() string {
	switch g {
	case flat:
		return "flat"
	case get:
		return "get"
	default:
		return "unknown"
	}
}

// Command returns the dummy command of the command group.
func (g commandGroup) Command(root *cobra.Command) (cmd *cobra.Command) {
	switch g {
	case get:
		if cmd, ok := groups[get]; ok {
			return cmd
		}
		cmd = &cobra.Command{
			Use:   g.String(),
			Short: "Get the status or resource of a topic",
			Long:  "Get the status or resource of a topic",
		}
		root.AddCommand(cmd)
		groups[get] = cmd
	case flat:
		cmd = root
	default:
		cmd = root
	}
	return cmd
}

const (
	// TagKey is the tag name of the antctl specific annotation.
	// For example:
	// 	type FooResponse struct {
	// 		Bar BarType `antctl:"key"`
	// 	}
	TagKey = "antctl"
	// TagOptionKeyArg is the option for antctl annotation. It tells the antctl the field is a primary key.
	TagOptionKeyArg = "key"
)

// ArgOption defines a argument to be used in a RequestOption.
type ArgOption struct {
	Name      string
	FieldName string
	Usage     string
	Key       bool
}

// CommandOption defines options to create a cobra.Command for antctl.
type CommandOption struct {
	// Cobra related
	Use   string
	Short string
	Long  string
	// Example will be filled with generated examples if it is not provided.
	Example string
	// commandGroup represents the group of the command.
	CommandGroup commandGroup
	// Controller should be true if this command works on antrea-controller.
	Controller bool
	// Agent should be true if this command works on antrea-agent.
	Agent bool
	// Singleton should be true if the handler only returns a single object.
	// The antctl assumes the response data as a slice of objects by default.
	Singleton bool
	// antctl will not parse the response from the server if this is true
	PlainText bool
	// The handler factory of the command.
	HandlerFactory handlers.Factory
	// ResponseStruct is the response object data struct of the command.
	ResponseStruct interface{}
	// AddonTransform is used to transform or fill the data received from the handler. It could be nil.
	AddonTransform func(reader io.Reader, single bool) (interface{}, error)
}

// Validate the CommandOption.
func (co *CommandOption) Validate() []error {
	var errs []error
	if len(co.Use) == 0 { // must have a use string
		errs = append(errs, fmt.Errorf("the command does not have name"))
	}
	if co.HandlerFactory == nil { // must have a handler
		errs = append(errs, fmt.Errorf("%s: no handler specified", co.Use))
	}
	if co.ResponseStruct == nil && !co.PlainText { // must define its response struct
		errs = append(errs, fmt.Errorf("%s: no response struct", co.Use))
	}
	// must have only one key arg
	var hasKey bool
	for _, arg := range co.ArgOptions() {
		if arg.Key && hasKey {
			errs = append(errs, fmt.Errorf("%s has more than one key field", co.Use))
			break
		} else if arg.Key {
			hasKey = true
		}
	}
	return errs
}

// ArgOptions returns the list of arguments that could be used in a CommandOption.
func (co *CommandOption) ArgOptions() []*ArgOption {
	var ret []*ArgOption
	if co.ResponseStruct == nil {
		return ret
	}
	t := reflect.Indirect(reflect.ValueOf(co.ResponseStruct)).Type()

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		argOpt := &ArgOption{FieldName: f.Name}

		tags, err := structtag.Parse(string(f.Tag))
		if err != nil { // Broken cli tags, skip this field
			continue
		}

		jsonTag, err := tags.Get("json")
		if err != nil {
			argOpt.Name = strings.ToLower(f.Name)
		} else {
			argOpt.Name = jsonTag.Name
		}

		cliTag, err := tags.Get(TagKey)
		if err == nil {
			argOpt.Key = cliTag.Name == TagOptionKeyArg
			argOpt.Usage = strings.Join(cliTag.Options, ", ")
		}

		ret = append(ret, argOpt)
	}
	return ret
}

func (co *CommandOption) decode(r io.Reader, single bool) (interface{}, error) {
	var result interface{}

	t := reflect.Indirect(reflect.ValueOf(co.ResponseStruct)).Type()

	if single || co.Singleton {
		ref := reflect.New(t)
		err := json.NewDecoder(r).Decode(ref.Interface())
		if err != nil {
			return nil, err
		}
		result = ref.Interface()
	} else {
		ref := reflect.New(reflect.SliceOf(t))
		err := json.NewDecoder(r).Decode(ref.Interface())
		if err != nil {
			return nil, err
		}
		result = reflect.Indirect(ref).Interface()
	}

	return result, nil
}

func (co *CommandOption) format(cmd *cobra.Command, r io.Reader, w io.Writer, single bool) (err error) {
	var obj interface{}
	if co.AddonTransform != nil {
		obj, err = co.AddonTransform(r, single)
	}
	if err != nil {
		return err
	}
	if co.PlainText { // Output PlainText directly
		if co.AddonTransform != nil {
			_, err = fmt.Fprintln(w, obj)
		} else {
			var output string
			fmt.Fscan(r, &output)
			_, err = fmt.Fprintf(w, "%s\n", strings.Trim(output, "\""))
		}
		return err
	}
	if co.AddonTransform == nil {
		obj, err = co.decode(r, single)
	}
	// Output structure data in format
	format, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	switch format {
	case "json":
		var output bytes.Buffer
		err := json.NewEncoder(&output).Encode(obj)
		if err != nil {
			return err
		}
		var prettifiedBuf bytes.Buffer
		err = json.Indent(&prettifiedBuf, output.Bytes(), "", "  ")
		if err != nil {
			return err
		}
		_, err = io.Copy(w, &prettifiedBuf)
		return err
	case "yaml":
		return yaml.NewEncoder(w).Encode(obj)
	case "table": // TODO: Add table formatter
		panic("Implement it")
	default:
		return fmt.Errorf("Unsupport format type: %s", format)
	}
}

func (co *CommandOption) createCommandRunE(keyArg *ArgOption, client *Client) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		argMap := make(map[string]string)
		if len(args) > 0 {
			argMap[keyArg.Name] = args[0]
		}
		kcfgPath, _ := cmd.Flags().GetString("kubeconfig")
		resp, err := client.Do(cmd, &RequestOption{Kubeconfig: kcfgPath, Name: cmd.Name(), Args: argMap})
		if err != nil {
			return err
		}
		single := len(argMap) != 0
		return co.format(cmd, resp, os.Stdout, single)
	}
}

// ApplyToCommand applies the CommandOption to a cobra.Command with the Client which is already applied by the same CommandOption.
func (co *CommandOption) ApplyToCommand(cmd *cobra.Command, client *Client) {
	cmd.Use = co.Use
	cmd.Short = co.Short
	cmd.Long = co.Long
	cmd.Flags().DurationP("timeout", "t", 5*time.Second, "execute timeout")
	if !co.PlainText {
		cmd.Flags().StringP("output", "o", "json", "output format: json|yaml|table")
	}
	var keyArgOption *ArgOption
	argOpts := co.ArgOptions()
	for i := range argOpts {
		a := argOpts[i]
		if a.Key {
			cmd.Use += fmt.Sprintf(" [%s]", a.Name)
			cmd.Long += "\n\nArgs:\n" + fmt.Sprintf("  %s\t%s", a.Name, a.Usage)
			// save the key arg option
			keyArgOption = a
		}
	}
	// If no example is provided, then framework will generate some.
	if len(co.Example) == 0 {
		cmd.Example = co.GenerateExample(cmd, keyArgOption)
	} else {
		cmd.Example = co.Example
	}
	// Set key arg length validator to the command.
	if keyArgOption != nil {
		cmd.Args = cobra.MaximumNArgs(1)
	} else {
		cmd.Args = cobra.NoArgs
	}

	cmd.RunE = co.createCommandRunE(keyArgOption, client)
}

// GenerateExample generates examples according to the CommandOption.
func (co *CommandOption) GenerateExample(cmd *cobra.Command, key *ArgOption) string {
	var commands []string

	for iter := cmd; iter != nil; iter = iter.Parent() {
		commands = append(commands, iter.Name())
	}
	for i := 0; i < len(commands)/2; i++ {
		commands[i], commands[len(commands)-1-i] = commands[len(commands)-1-i], commands[i]
	}

	var buf bytes.Buffer
	typeName := reflect.Indirect(reflect.ValueOf(co.ResponseStruct)).Type().Name()
	dataName := strings.ToLower(strings.TrimSuffix(typeName, "Response"))

	if co.Singleton {
		fmt.Fprintf(&buf, "  Get the %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(commands, " "))
	} else {
		if key != nil {
			fmt.Fprintf(&buf, "  Get a %s\n", dataName)
			fmt.Fprintf(&buf, "  $ %s [%s]\n", strings.Join(commands, " "), key.Name)
		}
		fmt.Fprintf(&buf, "  Get the list of %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(commands, " "))
	}

	return buf.String()
}
