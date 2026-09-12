package govulncheck

import "testing"

func TestParsePrettyPrintedJSONStream(t *testing.T) {
	data := []byte(`{
  "config": {
    "scanner_name": "govulncheck"
  }
}
{
  "finding": {
    "osv": "GO-2021-0113",
    "trace": [
      {
        "module": "golang.org/x/text",
        "version": "v0.3.5",
        "package": "golang.org/x/text/language",
        "function": "Parse"
      },
      {
        "module": "sample/app",
        "package": "sample/app",
        "function": "main",
        "position": {
          "filename": "app/main.go",
          "line": 12
        }
      }
    ]
  }
}`)
	findings := parse(data)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if findings[0].Title != "Reachable Go vulnerability GO-2021-0113" {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
	if findings[0].Evidence == "" {
		t.Fatalf("expected trace evidence")
	}
	if findings[0].FilePath != "app/main.go" || findings[0].Line != 12 {
		t.Fatalf("expected calling location, got %s:%d", findings[0].FilePath, findings[0].Line)
	}
}
