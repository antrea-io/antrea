package flowexporter

import "strconv"

// NewConnectionKey creates 5-tuple of flow as connection key
func NewConnectionKey(conn *Connection) ConnectionKey {
	return ConnectionKey{conn.TupleOrig.SourceAddress.String(),
		strconv.FormatUint(uint64(conn.TupleOrig.SourcePort), 10),
		conn.TupleReply.SourceAddress.String(),
		strconv.FormatUint(uint64(conn.TupleReply.SourcePort), 10),
		strconv.FormatUint(uint64(conn.TupleOrig.Protocol), 10),
	}
}
