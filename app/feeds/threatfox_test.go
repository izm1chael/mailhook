package feeds

import (
	"strings"
	"testing"
)

func TestParseThreatFox_URLIOCs(t *testing.T) {
	csv := `# id,ioc,threat_type,ioc_type,malware
1,http://evil.com/payload,botnet_cc,url,Emotet
2,malware.example.org,botnet_cc,domain,Emotet
`
	got, err := parseThreatFox([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 IOCs, got %d: %v", len(got), got)
	}
	if got[0] != "http://evil.com/payload" {
		t.Errorf("url IOC: got %q", got[0])
	}
	if got[1] != "http://malware.example.org" {
		t.Errorf("domain IOC wrapped: got %q", got[1])
	}
}

func TestParseThreatFox_SkipsIPPort(t *testing.T) {
	csv := `# id,ioc,threat_type,ioc_type,malware
1,192.168.1.1:4444,botnet_cc,ip:port,Cobalt
`
	got, _ := parseThreatFox([]byte(csv))
	if len(got) != 0 {
		t.Errorf("expected no IOCs for ip:port, got %v", got)
	}
}

func TestParseThreatFox_SkipsHashIOCs(t *testing.T) {
	csv := `# id,ioc,threat_type,ioc_type,malware
1,d41d8cd98f00b204e9800998ecf8427e,malware,md5_hash,Generic
2,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,malware,sha256_hash,Generic
`
	got, _ := parseThreatFox([]byte(csv))
	if len(got) != 0 {
		t.Errorf("expected no IOCs for hash types, got %v", got)
	}
}

func TestParseThreatFox_SkipsShortRows(t *testing.T) {
	csv := `# id,ioc,threat_type,ioc_type,malware
1,http://evil.com
2,http://short.com,botnet_cc
`
	got, _ := parseThreatFox([]byte(csv))
	if len(got) != 0 {
		t.Errorf("expected no IOCs from short rows, got %v", got)
	}
}

func TestParseThreatFox_EmptyInput(t *testing.T) {
	got, err := parseThreatFox([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestParseThreatFox_MixedTypes(t *testing.T) {
	csv := `# id,ioc,threat_type,ioc_type,malware
1,http://a.com/path,botnet_cc,url,X
2,10.0.0.1:80,botnet_cc,ip:port,X
3,abc.org,botnet_cc,domain,X
4,deadbeef,malware,md5_hash,X
`
	got, _ := parseThreatFox([]byte(csv))
	if len(got) != 2 {
		t.Fatalf("want 2 (url+domain), got %d: %v", len(got), got)
	}
	if !strings.HasPrefix(got[1], "http://") {
		t.Errorf("domain should be wrapped with http://, got %q", got[1])
	}
}
