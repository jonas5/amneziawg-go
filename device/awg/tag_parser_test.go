package awg

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	type args struct {
		name  string
		input string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "invalid name",
			args:    args{name: "apple", input: ""},
			wantErr: fmt.Errorf("empty input: "),
		},
		{
			name:    "empty",
			args:    args{name: "i1", input: ""},
			wantErr: fmt.Errorf("empty input: "),
		},
		{
			name:    "extra >",
			args:    args{name: "i1", input: "<b 0xf6ab3267fa><c>>"},
			wantErr: fmt.Errorf("ill formated input: <b 0xf6ab3267fa><c>>"),
		},
		{
			name:    "extra <",
			args:    args{name: "i1", input: "<<b 0xf6ab3267fa><c>"},
			wantErr: fmt.Errorf("empty tag in input: [ b 0xf6ab3267fa> c>]"),
		},
		{
			name:    "empty <>",
			args:    args{name: "i1", input: "<><b 0xf6ab3267fa><c>"},
			wantErr: fmt.Errorf("empty tag in input: [> b 0xf6ab3267fa> c>]"),
		},
		{
			name:    "invalid tag",
			args:    args{name: "i1", input: "<q 0xf6ab3267fa>"},
			wantErr: fmt.Errorf("invalid tag: q"),
		},
		{
			name:    "counter uniqueness violation",
			args:    args{name: "i1", input: "<c><c>"},
			wantErr: fmt.Errorf("tag c needs to be unique"),
		},
		{
			name:    "timestamp uniqueness violation",
			args:    args{name: "i1", input: "<t><t>"},
			wantErr: fmt.Errorf("tag t needs to be unique"),
		},
		{
			name: "valid",
			args: args{input: "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTagJunkGenerator(tt.args.name, tt.args.input)

			if tt.wantErr != nil {
				require.EqualError(t, err, tt.wantErr.Error())
				return
			}
			require.Nil(t, err)
		})
	}
}
