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

type CommandGroupType uint

var groups = map[CommandGroupType]*cobra.Command{}

func (cgt CommandGroupType) String() string {
	switch cgt {
	case Flat:
		return "flat"
	case Get:
		return "get"
	default:
		return "unknown"
	}
}

func (cgt CommandGroupType) Command(root *cobra.Command) (cmd *cobra.Command) {
	switch cgt {
	case Get:
		if cmd, ok := groups[Get]; ok {
			return cmd
		}
		cmd = &cobra.Command{
			Use:   cgt.String(),
			Short: "Get the status or resource of a topic",
			Long:  "Get the status or resource of a topic",
		}
		root.AddCommand(cmd)
		groups[Get] = cmd
	case Flat:
		cmd = root
	default:
		cmd = root
	}
	return cmd
}

const (
	Flat CommandGroupType = iota
	Get
)

const (
	// TagKey is the tag name of the antctl specific annotation.
	// For example:
	// 	type Foo struct {
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
	// Example will be filled generated examples if it is not provided.
	Example string
	// CommandGroup represents the group of the command.
	CommandGroup CommandGroupType
	// Controller should be true if this command works on antrea-controller.
	Controller bool
	// Agent should be true if this command works on antrea-agent.
	Agent bool
	// Singleton should be true if the handler only returns a single object.
	// The antctl assumes the response data as a slice of objects by default.
	Singleton bool
	// The handler factory of the command.
	HandlerFactory handlers.Factory
	// ResponseStruct is the response object data struct of the command.
	ResponseStruct interface{}
	// AddOnTransform is used to transform or fill the data received from the handler. It could be nil.
	AddOnTransform func(interface{}) interface{}
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

	if co.ResponseStruct == nil { // must defines its response struct
		errs = append(errs, fmt.Errorf("%s: no response struct", co.Use))
	}

	// must have only one key arg
	var hasKey bool
	for _, arg := range co.ArgOptions() {
		if arg.Key {
			if hasKey {
				errs = append(errs, fmt.Errorf("%s has more than one key field", co.Use))
				break
			}
			hasKey = true
		}
	}

	return errs
}

// ArgOptions returns the list of arguments could be used in a CommandOption.
func (co *CommandOption) ArgOptions() []*ArgOption {
	var ret []*ArgOption
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

func (co *CommandOption) decode(cmd *cobra.Command, r io.Reader, single bool) (interface{}, error) {
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

func (co *CommandOption) format(cmd *cobra.Command, obj interface{}, w io.Writer, single bool) error {
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
		io.Copy(w, &prettifiedBuf)
		return nil
	case "yaml":
		return yaml.NewEncoder(w).Encode(obj)
	case "table":
		// TODO: Add table formatter
		panic("Implement it")
	default:
		return fmt.Errorf("not support format type: %s", format)
	}
}

func (co *CommandOption) commandRun(keyArg *ArgOption, client *Client) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		argMap := make(map[string]string)

		if len(args) > 0 {
			argMap[keyArg.Name] = args[0]
		}

		cfgPath, _ := cmd.Flags().GetString("kubeconfig")
		resp, err := client.Do(cmd, &RequestOption{
			Kubeconfig: cfgPath,
			Name:       cmd.Name(),
			Args:       argMap,
		})
		if err != nil {
			return err
		}

		single := len(argMap) != 0

		obj, err := co.decode(cmd, resp, single)
		if err != nil {
			return err
		}
		if co.AddOnTransform != nil {
			obj = co.AddOnTransform(obj)
		}
		return co.format(cmd, obj, os.Stdout, single)
	}
}

// ApplyToCommand applies the CommandOption to a cobra.Command with the Client which is already applied by the same CommandOption.
func (co *CommandOption) ApplyToCommand(cmd *cobra.Command, client *Client) error {
	cmd.Use = co.Use
	cmd.Short = co.Short
	cmd.Long = co.Long
	cmd.Flags().DurationP("timeout", "t", 5*time.Second, "Execute timeout")
	cmd.Flags().StringP("output", "o", "json", "Output format: json|yaml|table")

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

	// If no example is provided, use the generated one.
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

	cmd.RunE = co.commandRun(keyArgOption, client)

	return nil
}

// GenerateExample generates example string according to the CommandOption.
func (co *CommandOption) GenerateExample(cmd *cobra.Command, key *ArgOption) string {
	var segs []string
	iter := cmd
	for iter != nil {
		segs = append(segs, iter.Name())
		iter = iter.Parent()
	}
	for i := 0; i < len(segs)/2; i++ {
		segs[i], segs[len(segs)-1-i] = segs[len(segs)-1-i], segs[i]
	}

	var buf bytes.Buffer
	typeName := reflect.Indirect(reflect.ValueOf(co.ResponseStruct)).Type().Name()
	dataName := strings.ToLower(strings.TrimSuffix(typeName, "Response"))

	if co.Singleton {
		fmt.Fprintf(&buf, "  Get the %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(segs, " "))
	} else {
		if key != nil {
			fmt.Fprintf(&buf, "  Get a %s\n", dataName)
			fmt.Fprintf(&buf, "  $ %s [%s]\n", strings.Join(segs, " "), key.Name)
		}
		fmt.Fprintf(&buf, "  Get the list of %s\n", dataName)
		fmt.Fprintf(&buf, "  $ %s\n", strings.Join(segs, " "))
	}

	return buf.String()
}
