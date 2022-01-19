package antctl

import (
	"github.com/spf13/cobra"
)

var multiclusterCmd = &cobra.Command{
	Use:     "multicluster",
	Short:   "Apply feature or fetch information from multicluster",
	Long:    `Apply feature or fetch information from multicluster`,
	Aliases: []string{"mc"},
}

func init() {
	rootCmd.AddCommand(multiclusterCmd)
}
