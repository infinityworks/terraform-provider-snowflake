package resources

import (
	"github.com/chanzuckerberg/terraform-provider-snowflake/pkg/snowflake"
	"github.com/chanzuckerberg/terraform-provider-snowflake/pkg/validation"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var validMaskingPolicyPrivileges = NewPrivilegeSet(
	privilegeUsage,
	privilegeOwnership,
)
var maskingPolicyGrantSchema = map[string]*schema.Schema{
	"masking_policy_name": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Identifier for the masking policy; must be unique for your account.",
		ForceNew:    true,
	},
	"privilege": {
		Type:         schema.TypeString,
		Optional:     true,
		Description:  "The privilege to grant on the masking policy.",
		Default:      "USAGE",
		ValidateFunc: validation.ValidatePrivilege(validMaskingPolicyPrivileges.ToList(), true),
		ForceNew:     true,
	},
	"roles": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Description: "Grants privilege to these roles.",
		ForceNew:    true,
	},
	"with_grant_option": {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "When this is set to true, allows the recipient role to grant the privileges to other roles.",
		Default:     false,
		ForceNew:    true,
	},
}

// MaskingPolicyGrant returns a pointer to the resource representing a maskingPolicy grant
func MaskingPolicyGrant() *TerraformGrantResource {
	return &TerraformGrantResource{
		Resource: &schema.Resource{
			Create: CreateMaskingPolicyGrant,
			Read:   ReadMaskingPolicyGrant,
			Delete: DeleteMaskingPolicyGrant,

			Schema: maskingPolicyGrantSchema,
		},
		ValidPrivs: validMaskingPolicyPrivileges,
	}
}

// CreateMaskingPolicyGrant implements schema.CreateFunc
func CreateMaskingPolicyGrant(d *schema.ResourceData, meta interface{}) error {
	w := d.Get("maskingPolicy_name").(string)
	priv := d.Get("privilege").(string)
	grantOption := d.Get("with_grant_option").(bool)
	builder := snowflake.MaskingPolicyGrant(w)

	err := createGenericGrant(d, meta, builder)
	if err != nil {
		return err
	}

	grant := &grantID{
		ResourceName: w,
		Privilege:    priv,
		GrantOption:  grantOption,
	}
	dataIDInput, err := grant.String()
	if err != nil {
		return err
	}
	d.SetId(dataIDInput)

	return ReadMaskingPolicyGrant(d, meta)
}

// ReadMaskingPolicyGrant implements schema.ReadFunc
func ReadMaskingPolicyGrant(d *schema.ResourceData, meta interface{}) error {
	grantID, err := grantIDFromString(d.Id())
	if err != nil {
		return err
	}
	w := grantID.ResourceName
	priv := grantID.Privilege

	err = d.Set("maskingPolicy_name", w)
	if err != nil {
		return err
	}
	err = d.Set("privilege", priv)
	if err != nil {
		return err
	}
	err = d.Set("with_grant_option", grantID.GrantOption)
	if err != nil {
		return err
	}

	builder := snowflake.MaskingPolicyGrant(w)

	return readGenericGrant(d, meta, maskingPolicyGrantSchema, builder, false, validMaskingPolicyPrivileges)
}

// DeleteMaskingPolicyGrant implements schema.DeleteFunc
func DeleteMaskingPolicyGrant(d *schema.ResourceData, meta interface{}) error {
	grantID, err := grantIDFromString(d.Id())
	if err != nil {
		return err
	}
	w := grantID.ResourceName

	builder := snowflake.MaskingPolicyGrant(w)

	return deleteGenericGrant(d, meta, builder)
}
