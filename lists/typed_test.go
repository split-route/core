package lists

import "testing"

func TestParseTextReadsTypedEntriesAndSkipsPrograms(t *testing.T) {
	es, st, err := ParseText([]byte("keyword:tracker\nregexp:^ads[0-9]+\\.\nport:853\nfull:a.example.org\napp:/Applications/Foo.app\nprocess:curl\n||adblock.example^\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(es.Keywords) != 1 || len(es.Regexes) != 1 || len(es.Ports) != 1 || len(es.Domains) != 1 {
		t.Errorf("entries = %+v", es)
	}
	if len(es.Apps) != 0 || len(es.Processes) != 0 {
		t.Errorf("programs came in from a shared list: %+v", es)
	}
	// app:, process: (programs on one Mac) are invalid here, the adblock rule is "other".
	if st.Invalid != 2 || st.Other != 1 {
		t.Errorf("stats = %+v", st)
	}
}
