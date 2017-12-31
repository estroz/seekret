package main

import (
	"context"
	"os"

	"github.com/google/go-github/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	// Name of organization to search.
	orgName string
	// OAuth2 access token. Required for increased rate limits.
	accessToken string
)

var rootCmd = &cobra.Command{
	Use:   "skrt",
	Short: "Seekret is a sensitive data crawler for GitHub repositories",
	Run: func(cmd *cobra.Command, args []string) {

		ctx := context.Background()
		var client *github.Client
		if accessToken != "" {
			ts := oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: accessToken,
			})
			tc := oauth2.NewClient(ctx, ts)
			client = github.NewClient(tc)
		} else {
			client = github.NewClient(nil)
		}

		CrawlOrg(ctx, client, orgName)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&accessToken, "oauth-token", "", "OAuth2 access token. Required for increased rate limits.")
	rootCmd.PersistentFlags().StringVar(&orgName, "org", "", "GitHub organization name.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
