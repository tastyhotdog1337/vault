package pkiext

import (
	"bytes"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/pki"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/require"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
)

func TestOcspWithOpenSSL(t *testing.T) {
	tempDir := t.TempDir()
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	mountPoint := "pki"
	err := client.Sys().Mount(mountPoint, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	require.NoError(t, err, "failed mounting pki endpoint")

	resp, err := client.Logical().Write(mountPoint+"/root/generate/internal", map[string]interface{}{
		"key_type":    "ec",
		"common_name": "root-ca.com",
		"ttl":         "600h",
	})
	require.NoError(t, err, "error generating root ca")

	resp, err = client.Logical().Write(mountPoint+"/roles/testing", map[string]interface{}{
		"key_type":       "ec",
		"ttl":            "60m",
		"allow_any_name": true,
	})
	require.NoError(t, err, "error adding role: %v", err)
	require.NotNil(t, resp, "expected role info")

	resp, err = client.Logical().Write(mountPoint+"/issue/testing", map[string]interface{}{
		"common_name": "client.example.com",
	})
	require.NoError(t, err, "error generating leaf cert")
	require.NotNil(t, resp, "expected leaf cert info")
	require.NotNil(t, resp.Data, "expected leaf cert info")
	require.NotEmpty(t, resp.Data["serial_number"], "expected leaf serial number")
	serial := resp.Data["serial_number"].(string)
	caChain := resp.Data["ca_chain"].([]interface{})
	caChainFile := path.Join(tempDir, "ca-chain.pem")
	issuerFile := path.Join(tempDir, "issuer.pem")
	certFile := path.Join(tempDir, "cert-to-revoke.pem")
	outToTempFile(t, interfaceListToString(caChain, "\n"), caChainFile)
	outToTempFile(t, resp.Data["issuing_ca"].(string), issuerFile)
	outToTempFile(t, resp.Data["certificate"].(string), certFile)

	cmd := exec.Command("openssl", "ocsp", "-no_nonce", "-issuer",
		issuerFile, "-CAfile", caChainFile, "-cert", certFile,
		"-url", client.Address()+"/v1/pki/ocsp")

	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	require.NoError(t, err, "failed running openssl command: %s", cmd.String())
	require.Contains(t, out.String(), ": good", "")

	resp, err = client.Logical().Write(mountPoint+"/revoke", map[string]interface{}{
		"serial_number": serial,
	})
	require.NoError(t, err, "error revoking leaf cert")
	require.NotNil(t, resp, "expected revocation info")

	cmd = exec.Command("openssl", "ocsp", "-no_nonce", "-issuer",
		issuerFile, "-CAfile", caChainFile, "-cert", certFile,
		"-url", client.Address()+"/v1/pki/ocsp")

	out = bytes.Buffer{}
	cmd.Stdout = &out
	err = cmd.Run()
	require.NoError(t, err, "failed running openssl command: %s", cmd.String())
	require.Contains(t, out.String(), ": revoked", "")
}

func outToTempFile(t *testing.T, contents, filename string) {
	err := os.WriteFile(filename, []byte(contents), 0600)
	require.NoError(t, err, "failed writing out %s", filename)
	if err != nil {
		return
	}
}

func interfaceListToString(interfaceVal []interface{}, separator string) string {
	var newVal []string
	for _, val := range interfaceVal {
		newVal = append(newVal, val.(string))
	}

	return strings.Join(newVal, separator)
}
