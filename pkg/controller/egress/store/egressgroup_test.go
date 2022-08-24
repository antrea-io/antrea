package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	types2 "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/controller/types"
)

func TestWatchEgressGroupEvent(t *testing.T) {
	egTypeInvalid := types.EgressGroup{}

	egressName := "egress"
	egressUID := types2.UID("uid")
	eg1 := &types.EgressGroup{
		SpanMeta:          types.SpanMeta{NodeNames: sets.NewString("node-local")},
		UID:               egressUID,
		Name:              egressName,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{},
	}

	eg2 := &types.EgressGroup{
		SpanMeta:          types.SpanMeta{NodeNames: sets.NewString("node1", "node2")},
		UID:               egressUID,
		Name:              egressName,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{},
	}

	pod1 := &controlplane.PodReference{Name: "pod1", Namespace: "namespace1"}
	eg3 := &types.EgressGroup{
		SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node-local")},
		UID:      egressUID,
		Name:     egressName,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{
			"node-local": controlplane.NewGroupMemberSet(&controlplane.GroupMember{Pod: pod1}),
		},
	}

	tests := []struct {
		name           string
		fieldSelector  fields.Selector
		operations     func(p storage.Interface)
		expectedEvents []watch.Event
	}{
		{
			name:          "Add event",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-local"}),
			operations: func(store storage.Interface) {
				store.Create(egTypeInvalid)
				store.Create(eg1)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: nil,
				}},
			},
		},
		{
			name:          "Delete event",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-local"}),
			operations: func(store storage.Interface) {
				store.Create(eg1)
				store.Update(eg2)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: nil,
				}},
				{Type: watch.Deleted, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: nil,
				}},
			},
		},
		{
			name:          "Modify event",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-local"}),
			operations: func(store storage.Interface) {
				store.Create(eg1)
				store.Update(eg1)
				store.Update(eg3)
				store.Update(eg3)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: nil,
				}},
				{Type: watch.Modified, Object: &controlplane.EgressGroupPatch{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					AddedGroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
			},
		},
		{
			name:          "Node not Specified",
			fieldSelector: fields.Everything(),
			operations: func(store storage.Interface) {
				store.Create(eg1)
				store.Update(eg3)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: nil,
				}},
				{Type: watch.Modified, Object: &controlplane.EgressGroupPatch{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					AddedGroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
			},
		},
	}
	for _, tc := range tests {
		store := NewEgressGroupStore()
		w, err := store.Watch(context.Background(), "", labels.Everything(), tc.fieldSelector)
		if err != nil {
			t.Fatalf("Failed to watch object: %v", err)
		}
		tc.operations(store)
		ch := w.ResultChan()
		for _, expectedEvent := range tc.expectedEvents {
			select {
			case actualEvent := <-ch:
				if !assert.Equal(t, expectedEvent, actualEvent) {
					t.Errorf("Expected event %v, got %v", expectedEvent, actualEvent)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Wait expected event timeout")
			}
		}
		select {
		case obj, ok := <-ch:
			t.Errorf("Unexpected excess event: %v %t", obj, ok)
		default:
		}
	}
}
