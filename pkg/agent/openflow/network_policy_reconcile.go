// Copyright 2026 Antrea Authors
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

package openflow

import (
	"fmt"
	"maps"

	"antrea.io/libOpenflow/openflow15"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/types"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
)

// policyRuleFlowTransaction stages only the contexts touched by a reconciliation. Installed contexts remain
// unchanged until the bundle succeeds, including contexts referenced by conjunctions outside the transaction.
type policyRuleFlowTransaction struct {
	feature  *featureNetworkPolicy
	contexts map[string]*conjMatchFlowContext
}

func (t *policyRuleFlowTransaction) context(match *conjunctiveMatch) *conjMatchFlowContext {
	key := match.generateGlobalMapKey()
	if ctx, found := t.contexts[key]; found {
		return ctx
	}
	var ctx *conjMatchFlowContext
	if installed, found := t.feature.globalConjMatchFlowCache[key]; found {
		staged := *installed
		staged.actions = maps.Clone(installed.actions)
		staged.denyAllRules = maps.Clone(installed.denyAllRules)
		ctx = &staged
	} else {
		ctx = &conjMatchFlowContext{
			conjunctiveMatch:     match,
			featureNetworkPolicy: t.feature,
			actions:              make(map[uint32]*conjunctiveAction),
		}
	}
	t.contexts[key] = ctx
	return ctx
}

func (t *policyRuleFlowTransaction) addMatch(clause *clause, match *conjunctiveMatch, enableLogging, isMCNPRule bool) error {
	key := match.generateGlobalMapKey()
	if _, found := clause.matches[key]; found {
		return nil
	}
	ctx := t.context(match)
	if clause.action.nClause > 1 {
		if len(ctx.actions) >= maxActionsPerConjMatchFlow {
			return newConjMatchFlowCapError(clause.action.conjID, key)
		}
		ctx.actions[clause.action.conjID] = clause.action
	} else {
		ctx.addDenyAllRule(clause.action.conjID)
	}
	if clause.dropTable != nil && (ctx.dropFlow == nil || ctx.dropFlowEnableLogging != enableLogging) {
		if isMCNPRule {
			ctx.dropFlow = getFlowModMessage(t.feature.multiClusterNetworkPolicySecurityDropFlow(clause.dropTable, match.matchPairs), binding.AddMessage)
		} else {
			ctx.dropFlow = getFlowModMessage(t.feature.defaultDropFlow(clause.dropTable, match.matchPairs, enableLogging), binding.AddMessage)
		}
		ctx.dropFlowEnableLogging = enableLogging
	}
	clause.matches[key] = ctx
	return nil
}

// ReconcilePolicyRuleFlows replaces the conjunctions for one logical rule in an atomic bundle. Retained IDs preserve
// their action and metric flows; only their addresses may change. The action cap applies to the final set of actions,
// after removing all previous contributions, so service groups can exchange addresses even at the cap.
func (c *client) ReconcilePolicyRuleFlows(previousIDs []uint32, desiredRules []*types.PolicyRule) ([]string, error) {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	f := c.featureNetworkPolicy
	f.conjMatchFlowLock.Lock()
	defer f.conjMatchFlowLock.Unlock()

	t := &policyRuleFlowTransaction{feature: f, contexts: make(map[string]*conjMatchFlowContext)}
	previous := make(map[uint32]*policyRuleConjunction, len(previousIDs))
	for _, id := range previousIDs {
		conj := f.getPolicyRuleConjunction(id)
		if conj == nil {
			return nil, newConjunctionNotFound(id)
		}
		previous[id] = conj
		for _, clause := range []*clause{conj.fromClause, conj.toClause, conj.serviceClause} {
			if clause == nil {
				continue
			}
			for _, installed := range clause.matches {
				ctx := t.context(installed.conjunctiveMatch)
				delete(ctx.actions, id)
				ctx.delDenyAllRule(id)
			}
		}
	}

	desired := make(map[uint32]*policyRuleConjunction, len(desiredRules))
	var adds, mods, dels []*openflow15.FlowMod
	for _, rule := range desiredRules {
		if _, found := desired[rule.FlowID]; found {
			return nil, fmt.Errorf("duplicate desired conjunction %d", rule.FlowID)
		}
		old := previous[rule.FlowID]
		if old == nil && f.getPolicyRuleConjunction(rule.FlowID) != nil {
			return nil, fmt.Errorf("conjunction %d is not part of this reconciliation", rule.FlowID)
		}
		var conj *policyRuleConjunction
		if old != nil {
			// A retained service group keeps its counters and conntrack identity.
			staged := *old
			staged.fromClause, staged.toClause, staged.serviceClause = nil, nil, nil
			staged.calculateClauses(rule)
			conj = &staged
		} else {
			conj = f.newPolicyRuleConjunction(rule)
			adds = append(adds, conj.actionFlows...)
			adds = append(adds, conj.metricFlows...)
		}
		if err := conj.forEachMatch(rule, f.ipProtocols, t.addMatch); err != nil {
			return nil, fmt.Errorf("error reconciling conjunctive match flows for %s: %w", conj.policyRuleString(), err)
		}
		desired[conj.id] = conj
	}
	for id, conj := range previous {
		if _, retained := desired[id]; !retained {
			dels = append(dels, conj.actionFlows...)
			dels = append(dels, conj.metricFlows...)
		}
	}

	// Emit a single change per match, using its final actions and isolation requirement.
	appendChange := func(before, after *openflow15.FlowMod) {
		switch {
		case before == after:
		case before == nil:
			adds = append(adds, after)
		case after == nil:
			dels = append(dels, before)
		default:
			mods = append(mods, after)
		}
	}
	for key, ctx := range t.contexts {
		before := f.globalConjMatchFlowCache[key]
		if before == nil {
			before = &conjMatchFlowContext{}
		}
		if !maps.EqualFunc(before.actions, ctx.actions, func(a, b *conjunctiveAction) bool { return *a == *b }) {
			ctx.flow = nil
			if len(ctx.actions) > 0 {
				actions := make([]*conjunctiveAction, 0, len(ctx.actions))
				for _, action := range ctx.actions {
					actions = append(actions, action)
				}
				ctx.flow = getFlowModMessage(f.conjunctiveMatchFlow(ctx.tableID, ctx.matchPairs, ctx.priority, actions), binding.AddMessage)
			}
		}
		if len(ctx.actions) == 0 && len(ctx.denyAllRules) == 0 {
			ctx.dropFlow = nil
		}
		appendChange(before.flow, ctx.flow)
		appendChange(before.dropFlow, ctx.dropFlow)
	}
	// The bridge sets FlowMod.Command in place. Give it private message headers so even a rejected bundle cannot
	// mutate cached messages that replay will use.
	cloneMessages := func(messages []*openflow15.FlowMod) []*openflow15.FlowMod {
		copies := make([]*openflow15.FlowMod, len(messages))
		for i, message := range messages {
			copy := *message
			copies[i] = &copy
		}
		return copies
	}
	if len(adds)+len(mods)+len(dels) > 0 {
		if err := c.ofEntryOperations.BundleOps(cloneMessages(adds), cloneMessages(mods), cloneMessages(dels)); err != nil {
			return nil, err
		}
	}

	for key, ctx := range t.contexts {
		if installed := f.globalConjMatchFlowCache[key]; installed != nil {
			// Other conjunctions still reference this object through clause.matches.
			*installed = *ctx
			t.contexts[key] = installed
		}
		if len(ctx.actions) == 0 && len(ctx.denyAllRules) == 0 {
			delete(f.globalConjMatchFlowCache, key)
		} else {
			f.globalConjMatchFlowCache[key] = t.contexts[key]
		}
	}
	for _, conj := range desired {
		for _, clause := range []*clause{conj.fromClause, conj.toClause, conj.serviceClause} {
			if clause == nil {
				continue
			}
			for key := range clause.matches {
				clause.matches[key] = t.contexts[key]
			}
		}
		if err := f.policyCache.Update(conj); err != nil {
			return nil, err
		}
	}
	for id, conj := range previous {
		if _, retained := desired[id]; !retained {
			if err := f.policyCache.Delete(conj); err != nil {
				return nil, err
			}
		}
	}
	stalePriorities := sets.New[string]()
	for id, conj := range previous {
		if _, retained := desired[id]; !retained {
			stalePriorities.Insert(f.getStalePriorities(conj)...)
		}
	}
	return sets.List(stalePriorities), nil
}
