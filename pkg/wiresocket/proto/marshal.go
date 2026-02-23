package proto

import (
	pb "google.golang.org/protobuf/proto"
)

// Marshal serialises f into protobuf wire format.
func (f *Frame) Marshal() []byte {
	b, _ := pb.Marshal(f)
	return b
}

// UnmarshalFrame parses a Frame from protobuf wire bytes.
func UnmarshalFrame(b []byte) (*Frame, error) {
	f := &Frame{}
	if err := pb.Unmarshal(b, f); err != nil {
		return nil, err
	}
	return f, nil
}
