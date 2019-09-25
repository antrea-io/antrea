package openflow

import (
	"fmt"
	"strings"
)

type commandBuilder struct {
	commandFlow
}

func (b *commandBuilder) Switch(name string) FlowBuilder {
	b.bridge = name
	return b
}

func (b *commandBuilder) Done() Flow {
	return &b.commandFlow
}

func (b *commandBuilder) MatchField(name, value string) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("%s=%s", name, value))
	return b
}

func (b *commandBuilder) MatchFieldRange(name, value string, rng Range) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("%s[%d..%d]=%s", name, rng[0], rng[1], value))
	return b
}

func (b *commandBuilder) CTState(value string) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("ct_state=%s", value))
	return b
}

func (b *commandBuilder) CTMark(value string) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("ct_mark=%s", value))
	return b
}

func (b *commandBuilder) MatchInPort(inPort int) FlowBuilder {
	return b.MatchField("in_port", fmt.Sprint(inPort))
}

func (b *commandBuilder) Priority(priority uint32) FlowBuilder {
	b.priority = priority
	return b
}

func (b *commandBuilder) Table(id TableIDType) FlowBuilder {
	b.table = id
	return b
}

func (b *commandBuilder) MatchProtocol(protocol protocol) FlowBuilder {
	b.matchers = append(b.matchers, strings.ToLower(protocol))
	return b
}

func (b *commandBuilder) Action() Action {
	return &commandAction{b}
}
