package resources_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAcc_MaskingPolicyGrants(t *testing.T) {
	wName := acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)
	roleName := acctest.RandStringFromCharSet(10, acctest.CharSetAlpha)

	resource.ParallelTest(t, resource.TestCase{
		Providers: providers(),
		Steps: []resource.TestStep{
			{
				Config: maskingPolicyGrantConfig(wName, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("snowflake_masking_policy_grant.test", "policy_name", wName),
					resource.TestCheckResourceAttr("snowflake_masking_policy_grant.test", "privilege", "MONITOR"),
				),
			},
		},
	})
}

func maskingPolicyGrantConfig(n, role string) string {
	return fmt.Sprintf(`
resource "snowflake_database" "test" {
  name = "%v"
  comment = "Terraform acceptance test"
}

resource "snowflake_schema" "test" {
  name = "%v"
  database = snowflake_database.test.name
  comment = "Terraform acceptance test"
}

resource "snowflake_masking_policy" "test" {
  name = "%v"
  database = snowflake_database.test.name
  schema = snowflake_schema.test.name
  value_data_type = "VARCHAR"
  masking_expression = "case when current_role() in ('ANALYST') then val else sha2(val, 512) end"
  return_data_type = "VARCHAR(16777216)"
  comment = "Terraform acceptance test"
}

resource "snowflake_role" "test" {
  name = "%v"
}

resource "snowflake_masking_policy_grant" "test" {
  masking_policy_name = snowflake_masking_policy.test.name
  roles          = [snowflake_role.test.name]
}
`, n, n, n, role)
}
