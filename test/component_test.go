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

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
