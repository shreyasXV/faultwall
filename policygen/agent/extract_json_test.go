package agent

import "testing"

// TestExtractJSONObject_Robust covers the parse failures seen in production:
// "invalid character '*' looking for beginning of value" caused by prose /
// bullets before the JSON, braces inside surrounding text, and multi-block
// Claude responses.
func TestExtractJSONObject_Robust(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bare object",
			in:   `{"schema":"x"}`,
			want: `{"schema":"x"}`,
		},
		{
			name: "leading bullet prose then fenced json",
			in:   "* Here is my analysis of the clusters\n```json\n{\"schema\":\"x\",\"summary\":\"s\"}\n```",
			want: `{"schema":"x","summary":"s"}`,
		},
		{
			name: "prose with stray braces before json",
			in:   "Note: use {curly} braces carefully.\n{\"schema\":\"x\"}",
			want: `{"schema":"x"}`,
		},
		{
			name: "brace inside string literal",
			in:   `{"summary":"a } brace and { another in text"}`,
			want: `{"summary":"a } brace and { another in text"}`,
		},
		{
			name: "escaped quote inside string",
			in:   `prefix {"summary":"she said \"hi\" }"} suffix`,
			want: `{"summary":"she said \"hi\" }"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractJSONObject(tc.in)
			if got != tc.want {
				t.Fatalf("extractJSONObject()\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestExtractJSONObject_NoBraces returns input unchanged so json.Unmarshal
// surfaces the real underlying error.
func TestExtractJSONObject_NoBraces(t *testing.T) {
	in := "* just a bullet, no json here"
	if got := extractJSONObject(in); got != in {
		t.Fatalf("want passthrough %q, got %q", in, got)
	}
}
