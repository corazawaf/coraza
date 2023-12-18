package cookies

import (
	"testing"
)

func equalMaps(map1 map[string][]string, map2 map[string][]string) bool {
	if len(map1) != len(map2) {
		return false
	}

	// Iterate through the key-value pairs of the first map
	for key, slice1 := range map1 {
		// Check if the key exists in the second map
		slice2, ok := map2[key]
		if !ok {
			return false
		}

		// Compare the values of the corresponding keys
		for i, val1 := range slice1 {
			val2 := slice2[i]

			// Compare the elements
			if val1 != val2 {
				return false
			}
		}
	}

	return true
}

func TestParseCookies(t *testing.T) {
	type args struct {
		rawCookies string
	}
	tests := []struct {
		name string
		args args
		want map[string][]string
	}{
		{
			name: "EmptyString",
			args: args{rawCookies: "  "},
			want: map[string][]string{},
		},
		{
			name: "SimpleCookie",
			args: args{rawCookies: "test=test_value"},
			want: map[string][]string{"test": {"test_value"}},
		},
		{
			name: "MultipleCookies",
			args: args{rawCookies: "test1=test_value1; test2=test_value2"},
			want: map[string][]string{"test1": {"test_value1"}, "test2": {"test_value2"}},
		},
		{
			name: "SpacesInCookieName",
			args: args{rawCookies: " test1  =test_value1; test2  =test_value2"},
			want: map[string][]string{"test1": {"test_value1"}, "test2": {"test_value2"}},
		},
		{
			name: "SpacesInCookieValue",
			args: args{rawCookies: "test1=test   _value1; test2  =test_value2"},
			want: map[string][]string{"test1": {"test   _value1"}, "test2": {"test_value2"}},
		},
		{
			name: "EmptyCookie",
			args: args{rawCookies: ";;foo=bar"},
			want: map[string][]string{"foo": {"bar"}},
		},
		{
			name: "EmptyName",
			args: args{rawCookies: "=bar;"},
			want: map[string][]string{},
		},
		{
			name: "MultipleEqualsInValues",
			args: args{rawCookies: "test1=val==ue1;test2=value2"},
			want: map[string][]string{"test1": {"val==ue1"}, "test2": {"value2"}},
		},
		{
			name: "RepeatedCookieNameShouldGiveList",
			args: args{rawCookies: "test1=value1;test1=value2"},
			want: map[string][]string{"test1": {"value1", "value2"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCookies(tt.args.rawCookies)
			if !equalMaps(got, tt.want) {
				t.Errorf("ParseCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}
