package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/stretchr/testify/assert"
)

type AssumeRolePolicyDocument struct {
	Statement []struct {
		Principal struct {
			Service string `json:"Service"`
		} `json:"Principal"`
		Action    []string                       `json:"Action"`
		Condition map[string]map[string][]string `json:"Condition"`
	} `json:"Statement"`
}

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "iam-role/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	policyNameSuffix := strings.ToLower(random.UniqueId())
	policyName := "role-policy-" + policyNameSuffix

	inputs := map[string]interface{}{
		"policy_name": policyName,
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	role := map[string]interface{}{}
	atmos.OutputStruct(s.T(), options, "role", &role)

	arn := role["arn"].(string)
	assert.NotEmpty(s.T(), arn)
	assert.Contains(s.T(), arn, "arn:aws:iam::")

	id := role["id"].(string)
	assert.NotEmpty(s.T(), id)

	instanceProfile := role["instance_profile"].(string)
	assert.NotEmpty(s.T(), instanceProfile)
	assert.Contains(s.T(), instanceProfile, "role")

	name := role["name"].(string)
	assert.NotEmpty(s.T(), name)
	assert.True(s.T(), strings.HasPrefix(name, "eg-default-ue2-test-role"))

	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), name, *awsRole.RoleName)
	assert.Equal(s.T(), "Used with AWS Workspaces Directory.\n", *awsRole.Description)

	assert.EqualValues(s.T(), 3600, *awsRole.MaxSessionDuration)
	assert.Equal(s.T(), "arn:aws:iam::aws:policy/PowerUserAccess", *awsRole.PermissionsBoundary.PermissionsBoundaryArn)
	assert.Equal(s.T(), "/", *awsRole.Path)

	awsInstanceProfile, err := client.GetInstanceProfile(context.Background(), &iam.GetInstanceProfileInput{
		InstanceProfileName: &name,
	})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), name, *awsInstanceProfile.InstanceProfile.InstanceProfileName)

	assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	var assumePolicyDoc AssumeRolePolicyDocument
	err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
	assert.NoError(s.T(), err)

	assert.Equal(s.T(), "workspaces.amazonaws.com", assumePolicyDoc.Statement[0].Principal.Service)
	assert.ElementsMatch(s.T(), []string{
		"sts:AssumeRole",
		"sts:SetSourceIdentity",
		"sts:TagSession",
	}, assumePolicyDoc.Statement[0].Action)

	// Verify assume role conditions
	assert.NotNil(s.T(), assumePolicyDoc.Statement[0].Condition)
	assert.Contains(s.T(), assumePolicyDoc.Statement[0].Condition, "StringLike")
	assert.Contains(s.T(), assumePolicyDoc.Statement[0].Condition["StringLike"], "aws:RequestTag/Environment")
	assert.ElementsMatch(s.T(), []string{"prod", "staging"},
		assumePolicyDoc.Statement[0].Condition["StringLike"]["aws:RequestTag/Environment"])

	attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	customPolicyArn := fmt.Sprintf("arn:aws:iam::799847381734:policy/%s", policyName)
	expectedPolicies := []string{
		customPolicyArn,
		"arn:aws:iam::aws:policy/AmazonWorkSpacesServiceAccess",
		"arn:aws:iam::aws:policy/AmazonWorkSpacesSelfServiceAccess",
	}

	var actualPolicies []string
	for _, policy := range attachedPolicies.AttachedPolicies {
		actualPolicies = append(actualPolicies, *policy.PolicyArn)
	}

	assert.ElementsMatch(s.T(), expectedPolicies, actualPolicies)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "iam-role/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func (s *ComponentSuite) TestAssumeRolePolicy() {
	const component = "iam-role/assume-role-policy"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	policyNameSuffix := strings.ToLower(random.UniqueId())
	policyName := "assume-role-policy-test-" + policyNameSuffix

	inputs := map[string]interface{}{
		"policy_name": policyName,
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	role := map[string]interface{}{}
	atmos.OutputStruct(s.T(), options, "role", &role)

	arn := role["arn"].(string)
	assert.NotEmpty(s.T(), arn)
	assert.Contains(s.T(), arn, "arn:aws:iam::")

	name := role["name"].(string)
	assert.NotEmpty(s.T(), name)
	assert.True(s.T(), strings.HasPrefix(name, "eg-default-ue2-test-assume-role-policy-role"))

	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), name, *awsRole.RoleName)
	assert.Equal(s.T(), "Used for testing assume_role_policy override.\n", *awsRole.Description)

	assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	var assumePolicyDoc struct {
		Statement []struct {
			Principal struct {
				Service string `json:"Service"`
			} `json:"Principal"`
			Action interface{} `json:"Action"`
		} `json:"Statement"`
	}
	err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
	assert.NoError(s.T(), err)

	assert.Equal(s.T(), "ec2.amazonaws.com", assumePolicyDoc.Statement[0].Principal.Service)
	// Action can be string or []string, so handle both
	switch v := assumePolicyDoc.Statement[0].Action.(type) {
	case string:
		assert.Equal(s.T(), "sts:AssumeRole", v)
	case []interface{}:
		assert.Equal(s.T(), 1, len(v))
		assert.Equal(s.T(), "sts:AssumeRole", v[0])
	default:
		assert.Fail(s.T(), "unexpected type for Action")
	}

	attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	expectedPolicies := []string{
		"arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
	}

	var actualPolicies []string
	for _, policy := range attachedPolicies.AttachedPolicies {
		actualPolicies = append(actualPolicies, *policy.PolicyArn)
	}

	assert.Subset(s.T(), actualPolicies, expectedPolicies)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestGitHubOidc() {
	const component = "iam-role/github-oidc"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	policyNameSuffix := strings.ToLower(random.UniqueId())
	policyName := "github-oidc-policy-" + policyNameSuffix

	inputs := map[string]interface{}{
		"policy_name": policyName,
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	role := map[string]interface{}{}
	atmos.OutputStruct(s.T(), options, "role", &role)

	arn := role["arn"].(string)
	assert.NotEmpty(s.T(), arn)
	assert.Contains(s.T(), arn, "arn:aws:iam::")

	name := role["name"].(string)
	assert.NotEmpty(s.T(), name)
	assert.True(s.T(), strings.HasPrefix(name, "eg-default-ue2-test-github-oidc-role"))

	// Verify the GitHub OIDC assume role policy output
	githubAssumeRolePolicy := atmos.Output(s.T(), options, "github_assume_role_policy")
	assert.NotEmpty(s.T(), githubAssumeRolePolicy)

	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), name, *awsRole.RoleName)
	assert.Equal(s.T(), "Role for GitHub Actions to deploy infrastructure via OIDC.\n", *awsRole.Description)

	assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	// Parse the assume role policy to verify GitHub OIDC configuration
	// Note: Condition values can be either string or []string, so we use interface{}
	var assumePolicyDoc struct {
		Statement []struct {
			Sid       string `json:"Sid"`
			Effect    string `json:"Effect"`
			Principal struct {
				Federated string `json:"Federated"`
			} `json:"Principal"`
			Action    interface{}                      `json:"Action"`
			Condition map[string]map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
	assert.NoError(s.T(), err)

	// Find the OIDC provider statement
	var oidcStatement *struct {
		Sid       string `json:"Sid"`
		Effect    string `json:"Effect"`
		Principal struct {
			Federated string `json:"Federated"`
		} `json:"Principal"`
		Action    interface{}                      `json:"Action"`
		Condition map[string]map[string]interface{} `json:"Condition"`
	}
	for i := range assumePolicyDoc.Statement {
		if assumePolicyDoc.Statement[i].Sid == "OidcProviderAssume" {
			oidcStatement = &assumePolicyDoc.Statement[i]
			break
		}
	}

	assert.NotNil(s.T(), oidcStatement, "Expected to find OidcProviderAssume statement")
	assert.Equal(s.T(), "Allow", oidcStatement.Effect)
	assert.Contains(s.T(), oidcStatement.Principal.Federated, "oidc-provider/token.actions.githubusercontent.com")

	// Verify the condition includes the audience check
	assert.NotNil(s.T(), oidcStatement.Condition)
	assert.Contains(s.T(), oidcStatement.Condition, "StringEquals")
	assert.Contains(s.T(), oidcStatement.Condition["StringEquals"], "token.actions.githubusercontent.com:aud")
	// Audience can be string or []string
	audValue := oidcStatement.Condition["StringEquals"]["token.actions.githubusercontent.com:aud"]
	switch v := audValue.(type) {
	case string:
		assert.Equal(s.T(), "sts.amazonaws.com", v)
	case []interface{}:
		assert.Contains(s.T(), v, "sts.amazonaws.com")
	default:
		assert.Fail(s.T(), "unexpected type for audience condition")
	}

	// Verify the condition includes the subject (repo) check
	assert.Contains(s.T(), oidcStatement.Condition, "StringLike")
	assert.Contains(s.T(), oidcStatement.Condition["StringLike"], "token.actions.githubusercontent.com:sub")

	// Verify the trusted repos are correctly formatted
	subValue := oidcStatement.Condition["StringLike"]["token.actions.githubusercontent.com:sub"]
	var subValues []string
	switch v := subValue.(type) {
	case string:
		subValues = []string{v}
	case []interface{}:
		for _, s := range v {
			subValues = append(subValues, s.(string))
		}
	}
	assert.Contains(s.T(), subValues, "repo:cloudposse/test-repo:*")
	assert.Contains(s.T(), subValues, "repo:cloudposse/infrastructure:ref:refs/heads/main")
	assert.Contains(s.T(), subValues, "repo:other-org/other-repo:ref:refs/heads/release/*")
	assert.Contains(s.T(), subValues, "repo:cloudposse/env-repo:environment:production")

	// Verify attached policies
	attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	expectedPolicies := []string{
		"arn:aws:iam::aws:policy/ReadOnlyAccess",
	}

	var actualPolicies []string
	for _, policy := range attachedPolicies.AttachedPolicies {
		actualPolicies = append(actualPolicies, *policy.PolicyArn)
	}

	assert.Subset(s.T(), actualPolicies, expectedPolicies)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestPolicyStatements() {
	const component = "iam-role/policy-statements"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	policyNameSuffix := strings.ToLower(random.UniqueId())
	policyName := "policy-statements-test-" + policyNameSuffix

	inputs := map[string]interface{}{
		"policy_name": policyName,
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	role := map[string]interface{}{}
	atmos.OutputStruct(s.T(), options, "role", &role)

	arn := role["arn"].(string)
	assert.NotEmpty(s.T(), arn)
	assert.Contains(s.T(), arn, "arn:aws:iam::")

	name := role["name"].(string)
	assert.NotEmpty(s.T(), name)
	assert.True(s.T(), strings.HasPrefix(name, "eg-default-ue2-test-policy-statements-role"))

	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), name, *awsRole.RoleName)
	assert.Equal(s.T(), "Role for testing YAML-friendly policy_statements variable.\n", *awsRole.Description)

	// Verify the assume role policy has Lambda service principal
	assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	var assumePolicyDoc AssumeRolePolicyDocument
	err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
	assert.NoError(s.T(), err)

	assert.Equal(s.T(), "lambda.amazonaws.com", assumePolicyDoc.Statement[0].Principal.Service)

	// Verify attached policies include Lambda basic execution role and the custom policy
	attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &name,
	})
	assert.NoError(s.T(), err)

	// Check that the Lambda basic execution role is attached
	var actualManagedPolicies []string
	var customPolicyArn string
	for _, policy := range attachedPolicies.AttachedPolicies {
		actualManagedPolicies = append(actualManagedPolicies, *policy.PolicyArn)
		// Find the custom policy created from policy_statements
		if strings.Contains(*policy.PolicyArn, policyName) {
			customPolicyArn = *policy.PolicyArn
		}
	}

	assert.Contains(s.T(), actualManagedPolicies, "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
	assert.NotEmpty(s.T(), customPolicyArn, "Expected to find custom policy from policy_statements")

	// Get the custom policy document and verify its contents
	if customPolicyArn != "" {
		policyOutput, err := client.GetPolicy(context.Background(), &iam.GetPolicyInput{
			PolicyArn: &customPolicyArn,
		})
		assert.NoError(s.T(), err)

		// Get the default version of the policy
		policyVersionOutput, err := client.GetPolicyVersion(context.Background(), &iam.GetPolicyVersionInput{
			PolicyArn: &customPolicyArn,
			VersionId: policyOutput.Policy.DefaultVersionId,
		})
		assert.NoError(s.T(), err)

		policyDocument, err := url.QueryUnescape(*policyVersionOutput.PolicyVersion.Document)
		assert.NoError(s.T(), err)

		// Parse the policy document
		var policyDoc struct {
			Version   string `json:"Version"`
			Statement []struct {
				Sid       string      `json:"Sid"`
				Effect    string      `json:"Effect"`
				Action    interface{} `json:"Action"`
				Resource  interface{} `json:"Resource"`
				Condition interface{} `json:"Condition,omitempty"`
			} `json:"Statement"`
		}
		err = json.Unmarshal([]byte(policyDocument), &policyDoc)
		assert.NoError(s.T(), err)

		assert.Equal(s.T(), "2012-10-17", policyDoc.Version)
		assert.GreaterOrEqual(s.T(), len(policyDoc.Statement), 3, "Expected at least 3 statements from policy_statements")

		// Verify we have the expected statement Sids
		var sids []string
		for _, stmt := range policyDoc.Statement {
			sids = append(sids, stmt.Sid)
		}
		assert.Contains(s.T(), sids, "AllowS3Read")
		assert.Contains(s.T(), sids, "AllowDynamoDBAccess")
		assert.Contains(s.T(), sids, "DenyDeleteOperations")

		// Find and verify the DenyDeleteOperations statement
		for _, stmt := range policyDoc.Statement {
			if stmt.Sid == "DenyDeleteOperations" {
				assert.Equal(s.T(), "Deny", stmt.Effect)
			}
		}
	}

	s.DriftTest(component, stack, &inputs)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
