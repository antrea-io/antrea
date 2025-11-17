package broadcaster

import "antrea.io/antrea/pkg/agent/flowexporter/connection"

type Subscriber interface {
	Subscribe() *subscription
	Unsubscribe(*subscription)
}

type Publisher interface {
	Publish(conns []*connection.Connection, l7EventMap map[connection.ConnectionKey]connection.L7ProtocolFields)
	PublishDeniedConnection(conn *connection.Connection)
}

type Broadcaster interface {
	Subscriber
	Publisher
	Start(stopCh <-chan struct{})
}
