package tls

import (
    "crypto/tls"
    "crypto/x509"
    "errors"
    "io/fs"
    "os"
    "path/filepath"
    "strings"
)

// LoadDir scans dir for PEM certificate / key pairs and returns a map keyed by DNS names (SNI) to *tls.Certificate.
// Matching rules:
//   - For every *.crt, *.pem or *.cert file, the loader looks for a key file with the same base name and extension .key or -key.pem.
//   - If both files exist and form a valid pair, all DNS names (CN + SANs) from the certificate are added as keys to the returned map.
//     The full lower-cased name as well as a wildcard-stripped form are included (e.g. "www.example.com" and "example.com").
// Certificates with parsing or validation errors are skipped but collected into the returned error slice.
func LoadDir(dir string) (map[string]*tls.Certificate, error) {
    res := make(map[string]*tls.Certificate)
    var errs []string

    walkFn := func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            errs = append(errs, err.Error())
            return nil
        }
        if d.IsDir() {
            return nil
        }
        name := d.Name()
        if !strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".cert") {
            return nil
        }
        base := strings.TrimSuffix(path, filepath.Ext(path))
        // candidate key names
        keyCandidates := []string{base + ".key", base + "-key.pem"}
        var keyPath string
        for _, k := range keyCandidates {
            if _, err := os.Stat(k); err == nil {
                keyPath = k
                break
            }
        }
        if keyPath == "" {
            errs = append(errs, "missing key for "+path)
            return nil
        }
        cert, err := tls.LoadX509KeyPair(path, keyPath)
        if err != nil {
            errs = append(errs, "invalid pair "+path+"/"+keyPath+": "+err.Error())
            return nil
        }
        // Parse leaf to extract names
        if len(cert.Certificate) == 0 {
            errs = append(errs, "empty certificate "+path)
            return nil
        }
        leaf, err := x509.ParseCertificate(cert.Certificate[0])
        if err != nil {
            errs = append(errs, "parse cert "+path+": "+err.Error())
            return nil
        }
        cert.Leaf = leaf
        addName := func(n string) {
            n = strings.ToLower(strings.TrimSpace(n))
            if n == "" {
                return
            }
            res[n] = &cert
        }
        addName(leaf.Subject.CommonName)
        for _, n := range leaf.DNSNames {
            addName(n)
        }
        return nil
    }
    _ = filepath.WalkDir(dir, walkFn)

    if len(errs) > 0 {
        return res, errors.New(strings.Join(errs, "; "))
    }
    return res, nil
}
