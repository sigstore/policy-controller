// Code generated by smithy-go-codegen DO NOT EDIT.

package kms

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Adds a grant to a KMS key.
//
// A grant is a policy instrument that allows Amazon Web Services principals to
// use KMS keys in cryptographic operations. It also can allow them to view a KMS
// key (DescribeKey ) and create and manage grants. When authorizing access to a KMS key,
// grants are considered along with key policies and IAM policies. Grants are often
// used for temporary permissions because you can create one, use its permissions,
// and delete it without changing your key policies or IAM policies.
//
// For detailed information about grants, including grant terminology, see [Grants in KMS] in the
// Key Management Service Developer Guide . For examples of working with grants in
// several programming languages, see [Programming grants].
//
// The CreateGrant operation returns a GrantToken and a GrantId .
//
//   - When you create, retire, or revoke a grant, there might be a brief delay,
//     usually less than five minutes, until the grant is available throughout KMS.
//     This state is known as eventual consistency. Once the grant has achieved
//     eventual consistency, the grantee principal can use the permissions in the grant
//     without identifying the grant.
//
// However, to use the permissions in the grant immediately, use the GrantToken
//
//	that CreateGrant returns. For details, see [Using a grant token]in the Key Management Service
//	Developer Guide .
//
//	- The CreateGrant operation also returns a GrantId . You can use the GrantId
//	and a key identifier to identify the grant in the RetireGrantand RevokeGrantoperations. To find the
//	grant ID, use the ListGrantsor ListRetirableGrantsoperations.
//
// The KMS key that you use for this operation must be in a compatible key state.
// For details, see [Key states of KMS keys]in the Key Management Service Developer Guide.
//
// Cross-account use: Yes. To perform this operation on a KMS key in a different
// Amazon Web Services account, specify the key ARN in the value of the KeyId
// parameter.
//
// Required permissions: [kms:CreateGrant] (key policy)
//
// Related operations:
//
// # ListGrants
//
// # ListRetirableGrants
//
// # RetireGrant
//
// # RevokeGrant
//
// Eventual consistency: The KMS API follows an eventual consistency model. For
// more information, see [KMS eventual consistency].
//
// [Programming grants]: https://docs.aws.amazon.com/kms/latest/developerguide/programming-grants.html
// [Key states of KMS keys]: https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
// [Grants in KMS]: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
// [kms:CreateGrant]: https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html
// [KMS eventual consistency]: https://docs.aws.amazon.com/kms/latest/developerguide/programming-eventual-consistency.html
//
// [Using a grant token]: https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token
func (c *Client) CreateGrant(ctx context.Context, params *CreateGrantInput, optFns ...func(*Options)) (*CreateGrantOutput, error) {
	if params == nil {
		params = &CreateGrantInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateGrant", params, optFns, c.addOperationCreateGrantMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateGrantOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type CreateGrantInput struct {

	// The identity that gets the permissions specified in the grant.
	//
	// To specify the grantee principal, use the Amazon Resource Name (ARN) of an
	// Amazon Web Services principal. Valid principals include Amazon Web Services
	// accounts, IAM users, IAM roles, federated users, and assumed role users. For
	// help with the ARN syntax for a principal, see [IAM ARNs]in the Identity and Access
	// Management User Guide .
	//
	// [IAM ARNs]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns
	//
	// This member is required.
	GranteePrincipal *string

	// Identifies the KMS key for the grant. The grant gives principals permission to
	// use this KMS key.
	//
	// Specify the key ID or key ARN of the KMS key. To specify a KMS key in a
	// different Amazon Web Services account, you must use the key ARN.
	//
	// For example:
	//
	//   - Key ID: 1234abcd-12ab-34cd-56ef-1234567890ab
	//
	//   - Key ARN:
	//   arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
	//
	// To get the key ID and key ARN for a KMS key, use ListKeys or DescribeKey.
	//
	// This member is required.
	KeyId *string

	// A list of operations that the grant permits.
	//
	// This list must include only operations that are permitted in a grant. Also, the
	// operation must be supported on the KMS key. For example, you cannot create a
	// grant for a symmetric encryption KMS key that allows the Signoperation, or a grant
	// for an asymmetric KMS key that allows the GenerateDataKeyoperation. If you try, KMS returns a
	// ValidationError exception. For details, see [Grant operations] in the Key Management Service
	// Developer Guide.
	//
	// [Grant operations]: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#terms-grant-operations
	//
	// This member is required.
	Operations []types.GrantOperation

	// Specifies a grant constraint.
	//
	// Do not include confidential or sensitive information in this field. This field
	// may be displayed in plaintext in CloudTrail logs and other output.
	//
	// KMS supports the EncryptionContextEquals and EncryptionContextSubset grant
	// constraints, which allow the permissions in the grant only when the encryption
	// context in the request matches ( EncryptionContextEquals ) or includes (
	// EncryptionContextSubset ) the encryption context specified in the constraint.
	//
	// The encryption context grant constraints are supported only on [grant operations] that include an
	// EncryptionContext parameter, such as cryptographic operations on symmetric
	// encryption KMS keys. Grants with grant constraints can include the DescribeKeyand RetireGrant
	// operations, but the constraint doesn't apply to these operations. If a grant
	// with a grant constraint includes the CreateGrant operation, the constraint
	// requires that any grants created with the CreateGrant permission have an
	// equally strict or stricter encryption context constraint.
	//
	// You cannot use an encryption context grant constraint for cryptographic
	// operations with asymmetric KMS keys or HMAC KMS keys. Operations with these keys
	// don't support an encryption context.
	//
	// Each constraint value can include up to 8 encryption context pairs. The
	// encryption context value in each constraint cannot exceed 384 characters. For
	// information about grant constraints, see [Using grant constraints]in the Key Management Service
	// Developer Guide. For more information about encryption context, see [Encryption context]in the Key
	// Management Service Developer Guide .
	//
	// [grant operations]: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#terms-grant-operations
	// [Using grant constraints]: https://docs.aws.amazon.com/kms/latest/developerguide/create-grant-overview.html#grant-constraints
	// [Encryption context]: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
	Constraints *types.GrantConstraints

	// Checks if your request will succeed. DryRun is an optional parameter.
	//
	// To learn more about how to use this parameter, see [Testing your KMS API calls] in the Key Management
	// Service Developer Guide.
	//
	// [Testing your KMS API calls]: https://docs.aws.amazon.com/kms/latest/developerguide/programming-dryrun.html
	DryRun *bool

	// A list of grant tokens.
	//
	// Use a grant token when your permission to call this operation comes from a new
	// grant that has not yet achieved eventual consistency. For more information, see [Grant token]
	// and [Using a grant token]in the Key Management Service Developer Guide.
	//
	// [Grant token]: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#grant_token
	// [Using a grant token]: https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token
	GrantTokens []string

	// A friendly name for the grant. Use this value to prevent the unintended
	// creation of duplicate grants when retrying this request.
	//
	// Do not include confidential or sensitive information in this field. This field
	// may be displayed in plaintext in CloudTrail logs and other output.
	//
	// When this value is absent, all CreateGrant requests result in a new grant with
	// a unique GrantId even if all the supplied parameters are identical. This can
	// result in unintended duplicates when you retry the CreateGrant request.
	//
	// When this value is present, you can retry a CreateGrant request with identical
	// parameters; if the grant already exists, the original GrantId is returned
	// without creating a new grant. Note that the returned grant token is unique with
	// every CreateGrant request, even when a duplicate GrantId is returned. All grant
	// tokens for the same grant ID can be used interchangeably.
	Name *string

	// The principal that has permission to use the RetireGrant operation to retire the grant.
	//
	// To specify the principal, use the [Amazon Resource Name (ARN)] of an Amazon Web Services principal. Valid
	// principals include Amazon Web Services accounts, IAM users, IAM roles, federated
	// users, and assumed role users. For help with the ARN syntax for a principal, see
	// [IAM ARNs]in the Identity and Access Management User Guide .
	//
	// The grant determines the retiring principal. Other principals might have
	// permission to retire the grant or revoke the grant. For details, see RevokeGrantand [Retiring and revoking grants] in
	// the Key Management Service Developer Guide.
	//
	// [IAM ARNs]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns
	// [Amazon Resource Name (ARN)]: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	// [Retiring and revoking grants]: https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#grant-delete
	RetiringPrincipal *string

	noSmithyDocumentSerde
}

type CreateGrantOutput struct {

	// The unique identifier for the grant.
	//
	// You can use the GrantId in a ListGrants, RetireGrant, or RevokeGrant operation.
	GrantId *string

	// The grant token.
	//
	// Use a grant token when your permission to call this operation comes from a new
	// grant that has not yet achieved eventual consistency. For more information, see [Grant token]
	// and [Using a grant token]in the Key Management Service Developer Guide.
	//
	// [Grant token]: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#grant_token
	// [Using a grant token]: https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token
	GrantToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateGrantMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpCreateGrant{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpCreateGrant{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "CreateGrant"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addOpCreateGrantValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateGrant(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opCreateGrant(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "CreateGrant",
	}
}
