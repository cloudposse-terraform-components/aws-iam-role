package test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
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

func TestComponent(t *testing.T) {
	awsRegion := "us-east-2"

	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			policyNameSuffix := strings.ToLower(random.UniqueId())
			policyName := "role-policy-" + policyNameSuffix

			inputs := map[string]interface{}{
				"policy_name": policyName,
			}

			defer atm.GetAndDestroy("iam-role/basic", "default-test", inputs)
			component := atm.GetAndDeploy("iam-role/basic", "default-test", inputs)
			assert.NotNil(t, component)

			role := map[string]interface{}{}
			atm.OutputStruct(component, "role", &role)

			arn := role["arn"].(string)
			assert.NotEmpty(t, arn)
			assert.Contains(t, arn, "arn:aws:iam::")

			id := role["id"].(string)
			assert.NotEmpty(t, id)

			instanceProfile := role["instance_profile"].(string)
			assert.NotEmpty(t, instanceProfile)
			assert.Contains(t, instanceProfile, "role")

			name := role["name"].(string)
			assert.NotEmpty(t, name)
			assert.True(t, strings.HasPrefix(name, "eg-default-ue2-test-role"))

			client := aws.NewIamClient(t, awsRegion)
			describeRoleOutput, err := client.GetRole(&iam.GetRoleInput{
				RoleName: &name,
			})
			assert.NoError(t, err)

			awsRole := describeRoleOutput.Role
			assert.Equal(t, name, *awsRole.RoleName)
			assert.Equal(t, "Used with AWS Workspaces Directory.\n", *awsRole.Description)

			assert.EqualValues(t, 3600, *awsRole.MaxSessionDuration)
			assert.Equal(t, "arn:aws:iam::aws:policy/PowerUserAccess", *awsRole.PermissionsBoundary.PermissionsBoundaryArn)
			assert.Equal(t, "/", *awsRole.Path)

			awsInstanceProfile, err := client.GetInstanceProfile(&iam.GetInstanceProfileInput{
				InstanceProfileName: &name,
			})
			assert.NoError(t, err)
			assert.Equal(t, name, *awsInstanceProfile.InstanceProfile.InstanceProfileName)

			assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
			assert.NoError(t, err)

			var assumePolicyDoc AssumeRolePolicyDocument
			err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
			assert.NoError(t, err)

			assert.Equal(t, "workspaces.amazonaws.com", assumePolicyDoc.Statement[0].Principal.Service)
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[0].Action)

			// Verify assume role conditions
			assert.NotNil(t, assumePolicyDoc.Statement[0].Condition)
			assert.Contains(t, assumePolicyDoc.Statement[0].Condition, "StringLike")
			assert.Contains(t, assumePolicyDoc.Statement[0].Condition["StringLike"], "aws:RequestTag/Environment")
			assert.ElementsMatch(t, []string{"prod", "staging"},
				assumePolicyDoc.Statement[0].Condition["StringLike"]["aws:RequestTag/Environment"])

			attachedPolicies, err := client.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
				RoleName: &name,
			})
			assert.NoError(t, err)

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

			assert.ElementsMatch(t, expectedPolicies, actualPolicies)
		})
	})
}
