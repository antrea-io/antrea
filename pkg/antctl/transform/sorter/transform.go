package sorter

import (
	//"encoding/json"
	"errors"
	"io"

	//"net"
	"reflect"
	"sort"

	//"strconv"
	//"time"
	"antrea.io/antrea/pkg/antctl/transform"
	"antrea.io/antrea/pkg/antctl/transform/common"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"

	"antrea.io/antrea/pkg/antctl/transform/addressgroup"
	"antrea.io/antrea/pkg/antctl/transform/appliedtogroup"
	"antrea.io/antrea/pkg/antctl/transform/networkpolicy"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubectl/pkg/cmd/get"
)

func objectTransform(o interface{}, _ map[string]string) (interface{}, error) {

	switch o.(type) {
	case *cpv1beta.NetworkPolicy:
		return networkpolicy.Response{o.(*cpv1beta.NetworkPolicy)}, nil

	case *cpv1beta.AddressGroup:
		group := o.(*cpv1beta.AddressGroup)
		var pods, nodes []common.GroupMember
		for _, member := range group.GroupMembers {
			gm := common.GroupMemberPodTransform(member)
			if member.Node != nil {
				nodes = append(nodes, gm)
				continue
			}
			pods = append(pods, gm)
		}
		return addressgroup.Response{Name: group.Name, Pods: pods, Nodes: nodes}, nil

	case *cpv1beta.AppliedToGroup:
		group := o.(*cpv1beta.AppliedToGroup)
		var pods []common.GroupMember
		for _, pod := range group.GroupMembers {
			pods = append(pods, common.GroupMemberPodTransform(pod))
		}
		return appliedtogroup.Response{Name: group.GetName(), Pods: pods}, nil
	default:
		return o, errors.New("please specify right resource ")

	}
}

func listTransform(l interface{}, opts map[string]string) (interface{}, error) {

	switch l.(type) {
	case *cpv1beta.NetworkPolicyList:
		policyList := l.(*cpv1beta.NetworkPolicyList)
		sortBy := ""
		if sb, ok := opts["sort-by"]; ok {
			sortBy = sb
		}
		//var nlist []cpv1beta.NetworkPolicy
		//flagvalue := sortByEffectivePriority, sortBycreationtime, sortByName, sortByresourceVersion
		//flagvalue = [4]string{"sortByEffectivePriority, sortBycreationtime, sortByName, sortByresourceVersion"}
		//const sortByEffectivePriority = "effectivePriority"
		const (
			sortBycreationtime string = ".metadata.creationTimestamp"
		)
		const (
			sortByname = ".metadata.name"
		)
		const (
			sortByresourceVersion = ".metadata.resourceVersion"
		)
		const (
			sortByuid = ".metadata.uid"
		)
		/*npSorter := &networkpolicy.NPSorter{
			NetworkPolicies: policyList.Items,
			SortBy:          sortBy,
		}*/
		switch sortBy {
		case sortBycreationtime:
			nlist := sortbynpflag(policyList, sortBycreationtime)
			result := make([]networkpolicy.Response, 0, len(policyList.Items))
			for i := range nlist.Items {
				o, _ := objectTransform(&nlist.Items[i], opts)
				result = append(result, o.(networkpolicy.Response))
			}
			return result, nil
		case sortByname:
			nlist := sortbynpflag(policyList, sortByname)
			result := make([]networkpolicy.Response, 0, len(policyList.Items))
			for i := range nlist.Items {
				o, _ := objectTransform(&nlist.Items[i], opts)
				result = append(result, o.(networkpolicy.Response))
			}
			return result, nil
		case sortByresourceVersion:
			nlist := sortbynpflag(policyList, sortByresourceVersion)
			result := make([]networkpolicy.Response, 0, len(policyList.Items))
			for i := range nlist.Items {
				o, _ := objectTransform(&nlist.Items[i], opts)
				result = append(result, o.(networkpolicy.Response))
			}
			return result, nil
		case sortByuid:
			nlist := sortbynpflag(policyList, sortByuid)
			result := make([]networkpolicy.Response, 0, len(policyList.Items))
			for i := range nlist.Items {
				o, _ := objectTransform(&nlist.Items[i], opts)
				result = append(result, o.(networkpolicy.Response))
			}
			return result, nil
		default:
			nlist := sortbynpflag(policyList, sortByname)
			result := make([]networkpolicy.Response, 0, len(policyList.Items))
			for i := range nlist.Items {
				o, _ := objectTransform(&nlist.Items[i], opts)
				result = append(result, o.(networkpolicy.Response))
			}
			return result, nil

		}
		/*nlist := sortbynpflag(policyList.Items, flagvalue)
		result := make([]networkpolicy.Response, 0, len(policyList.Items))
		for i := range nlist {
			o, _ := objectTransform(&nlist.Items[i], opts)
			result = append(result, o.(networkpolicy.Response))
		}
		return result, nil*/

	case *cpv1beta.AddressGroupList:
		groups := l.(*cpv1beta.AddressGroupList)
		sortBy := ""
		if sb, ok := opts["sort-by"]; ok {
			sortBy = sb
		}
		/*adsorter := &addressgroup.Adsorter{
			Addressgroups: groups.Items,
			SortBy:        sortBy,
		}*/
		flagvalue := sortBy
		adlist := sortbyadflag(groups.Items, flagvalue)

		result := make([]addressgroup.Response, 0, len(groups.Items))
		for i := range adlist {
			o, _ := objectTransform(&adlist[i], opts)
			result = append(result, o.(addressgroup.Response))
		}
		return result, nil

	case *cpv1beta.AppliedToGroupList:
		groups := l.(*cpv1beta.AppliedToGroupList)
		sortBy := ""
		if sb, ok := opts["sort-by"]; ok {
			sortBy = sb
		}
		apsorter := &appliedtogroup.Apsorter{
			Appliedtogroups: groups.Items,
			SortBy:          sortBy,
		}
		flagvalue := sortBy
		aplist := sortbyapflag(groups.Items, flagvalue)

		result := make([]appliedtogroup.Response, 0, len(groups.Items))
		for i := range aplist {
			o, _ := objectTransform(&apsorter.Appliedtogroups[i], opts)
			result = append(result, o.(appliedtogroup.Response))
		}
		return result, nil
	default:
		return l, errors.New("please specify right resource")

	}

}

func NPTransform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.NetworkPolicy{}),
		reflect.TypeOf(cpv1beta.NetworkPolicyList{}),
		objectTransform,
		listTransform,
		opts,
	)(reader, single)
}

func ADTransform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.AddressGroup{}),
		reflect.TypeOf(cpv1beta.AddressGroupList{}),
		objectTransform,
		listTransform,
		opts,
	)(reader, single)
}

func APTransform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.AppliedToGroup{}),
		reflect.TypeOf(cpv1beta.AppliedToGroupList{}),
		objectTransform,
		listTransform,
		opts,
	)(reader, single)
}

func sortbynpflag(npList *cpv1beta.NetworkPolicyList, flagv string) *cpv1beta.NetworkPolicyList {

	//var obj []runtime.Object
	obj, _ := meta.ExtractList(npList)
	runtimeSortName := get.NewRuntimeSort(flagv, obj)
	sort.Sort(runtimeSortName)
	return npList
}
func sortbyadflag(adList []cpv1beta.AddressGroup, flagv string) []cpv1beta.AddressGroup {

	var obj []runtime.Object
	runtimeSortName := get.NewRuntimeSort(flagv, obj)
	sort.Sort(runtimeSortName)
	return adList

}
func sortbyapflag(apList []cpv1beta.AppliedToGroup, flagv string) []cpv1beta.AppliedToGroup {

	var obj []runtime.Object
	runtimeSortName := get.NewRuntimeSort(flagv, obj)
	sort.Sort(runtimeSortName)
	return apList
}

/*objs, _ := meta.ExtractList(A)
fieldName := "{.metadata.name}"
runtimeSortName := get.NewRuntimeSort(fieldName, objs)
sort.Sort(runtimeSortName)
	for _, i := range objs {
	fmt.Println(i.(*corev1.Pod).Spec)


	}
*/
