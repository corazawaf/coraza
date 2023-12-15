package cookies

import (
	"reflect"
	"testing"
)

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
			args: args{rawCookies: "test1=value1;;test2=value2"},
			want: map[string][]string{"test1": {"value1"}, "test2": {"value2"}},
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
			if got := ParseCookies(tt.args.rawCookies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}
