package cmd

import (
	"os"
	// Embed the IANA timezone database so app.timezone resolves on Windows and
	// on scratch/distroless containers, which ship no system zoneinfo.
	_ "time/tzdata"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ao-identity-gateway",
	Short: "AlphaOmega Identity Gateway — IAM server",
}

func init() {
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(bootstrapCmd)
	// rootCmd.AddCommand(rotateKeysCmd)
}

// Execute runs the root command and exits non-zero on failure.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
