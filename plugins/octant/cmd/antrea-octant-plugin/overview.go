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

package main

import (
	"log"

	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"github.com/vmware-tanzu/octant/pkg/view/flexlayout"
)

const (
	overviewTitle = "Overview"
	antreaTitle   = "Antrea"
)

type getTableFunc func(request service.Request) *component.Table

// overviewHandler handlers the layout of Antrea Overview page.
func (p *antreaOctantPlugin) overviewHandler(request service.Request) (component.ContentResponse, error) {
	layout := flexlayout.New()
	listSection := layout.AddSection()
	handlers := []getTableFunc{
		p.getControllerTable,
		p.getAgentTable,
		p.getTfTable,
	}
	resp := component.NewContentResponse(component.TitleFromString(overviewTitle))
	err := listSection.Add(component.NewMarkdownText("## "+antreaTitle), component.WidthFull)
	if err != nil {
		log.Printf("Failed to load a tab in overview page, err: %v", err)
		return component.EmptyContentResponse, err
	}
	for _, handler := range handlers {
		table := handler(request)
		err := listSection.Add(table, component.WidthFull)
		if err != nil {
			log.Printf("Failed to load a tab in overview page, err: %v", err)
			return component.EmptyContentResponse, err
		}
	}
	resp.Components = append(resp.Components, layout.ToComponent(overviewTitle))
	return *resp, nil
}
