package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/iamkirkbater/creds/pkg/cache"
	"github.com/iamkirkbater/creds/pkg/saml"
)

var (
	account         string
	role            string
	region          string
	durationSeconds int32
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate via SAML and obtain AWS credentials",
	Long: `Authenticate using Kerberos/SAML to assume an AWS IAM role.
Credentials are cached locally and reused until they expire.

This command outputs credentials in the AWS credential_process JSON format,
making it suitable for use as an external credential provider in ~/.aws/config.`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().StringVar(&account, "account", "", "AWS account ID (required)")
	authCmd.Flags().StringVar(&role, "role", "", "IAM role name to assume (required)")
	authCmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region")
	authCmd.Flags().Int32Var(&durationSeconds, "duration", 3600, "Session duration in seconds")

	authCmd.MarkFlagRequired("account")
	authCmd.MarkFlagRequired("role")

	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	// Check cache first
	if creds, ok := cache.Load(account, role, region); ok {
		return outputJSON(creds)
	}

	// Fetch SAML token
	samlToken, err := saml.GetSAMLToken(saml.DefaultSAMLURL)
	if err != nil {
		return fmt.Errorf("failed to get SAML token: %w", err)
	}

	// Validate the requested role exists in the SAML assertion
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, role)
	principalArn := fmt.Sprintf("arn:aws:iam::%s:saml-provider/RedHatInternal", account)

	roles, err := saml.ParseRoles(samlToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse roles from SAML assertion: %v\n", err)
	} else {
		found := false
		for _, r := range roles {
			if r.RoleARN == roleArn && r.PrincipalARN == principalArn {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: requested role %s not found in SAML assertion.\n\nAvailable roles:\n", roleArn)
			roleARNs := make([]string, len(roles))
			for i, r := range roles {
				roleARNs[i] = r.RoleARN
			}
			sort.Strings(roleARNs)
			for _, arn := range roleARNs {
				fmt.Fprintf(os.Stderr, "  - %s\n", arn)
			}
			return fmt.Errorf("requested role not available in SAML assertion")
		}
	}

	stsClient := sts.New(sts.Options{
		Region: region,
		Credentials: aws.AnonymousCredentials{},
	})

	resp, err := stsClient.AssumeRoleWithSAML(context.Background(), &sts.AssumeRoleWithSAMLInput{
		RoleArn:         &roleArn,
		PrincipalArn:    &principalArn,
		SAMLAssertion:   &samlToken,
		DurationSeconds: &durationSeconds,
	})
	if err != nil {
		return fmt.Errorf("failed to assume role: %w", err)
	}

	creds := &cache.Credentials{
		Version:        1,
		AccessKeyId:    *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:   *resp.Credentials.SessionToken,
		Expiration:     resp.Credentials.Expiration.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Cache credentials
	if err := cache.Save(account, role, region, creds); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to cache credentials: %v\n", err)
	}

	return outputJSON(creds)
}

func outputJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(v)
}
