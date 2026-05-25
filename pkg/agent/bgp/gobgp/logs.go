// Copyright 2024 Antrea Authors
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

package gobgp

import (
	"context"
	"log/slog"
	"slices"

	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
)

type klogHandler struct {
	inner    slog.Handler // logr.ToSlogHandler(klog.NewKlogr())
	routerID string
	attrs    []slog.Attr
}

func (h *klogHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *klogHandler) Handle(ctx context.Context, r slog.Record) error {
	r = r.Clone() // preserves r.PC, so klog still reports the gobgp call site
	r.AddAttrs(slog.String("routerID", h.routerID))
	r.AddAttrs(h.attrs...) // re-inject attrs klog's slog sink would otherwise drop
	return h.inner.Handle(ctx, r)
}

func (h *klogHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &klogHandler{
		inner:    h.inner,
		routerID: h.routerID,
		attrs:    append(slices.Clone(h.attrs), a...),
	}
}

func (h *klogHandler) WithGroup(name string) slog.Handler {
	return &klogHandler{
		inner:    h.inner.WithGroup(name),
		routerID: h.routerID,
		attrs:    slices.Clone(h.attrs),
	}
}

func newGoBGPLogger(routerID string) (*slog.Logger, *slog.LevelVar) {
	levelVar := &slog.LevelVar{}
	levelVar.Set(slog.LevelDebug) // only consulted by gobgp's unused SetLogLevel RPC
	h := &klogHandler{
		inner:    logr.ToSlogHandler(klog.NewKlogr()),
		routerID: routerID,
	}
	return slog.New(h), levelVar
}
