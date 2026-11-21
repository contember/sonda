package aws

import (
	"context"
	"errors"
	"slices"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// lambdaAPI is the part of the Lambda client the connector uses. Not GetFunction: it returns a
// presigned URL that downloads the function's code.
type lambdaAPI interface {
	GetFunctionConfiguration(ctx context.Context, in *lambda.GetFunctionConfigurationInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error)
}

// FunctionConfig is a Lambda function's configuration without the values of its environment
// variables, which often hold credentials and which IAM cannot exclude from the response.
type FunctionConfig struct {
	Name             string
	Runtime          string
	Architectures    []string
	PackageType      string
	Handler          string
	MemoryMB         int
	TimeoutSeconds   int
	State            string
	StateReason      string
	LastUpdateStatus string
	LastModified     string
	CodeSize         int64
	Layers           []lambdatypes.Layer
	// EnvironmentNames are the names of the environment variables, sorted.
	EnvironmentNames []string
	// EnvironmentError is true when Lambda could not decrypt the variables; its message is
	// dropped, because it can echo key details.
	EnvironmentError bool
}

// Function reads the configuration of a bound function and drops every environment value
// before it leaves the connector.
func (c *Client) Function(ctx context.Context, scope authz.ResourceScope, name string) (FunctionConfig, error) {
	if !scope.HasLambda(name) {
		return FunctionConfig{}, c.outsideScope()
	}
	out, err := c.lambda.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: sdkaws.String(name)})
	var notFound *lambdatypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return FunctionConfig{}, apierr.Upstream("source %s: Lambda function %s not found", c.source.Name, name)
	}
	if err != nil {
		return FunctionConfig{}, c.apiError("GetFunctionConfiguration", err)
	}
	if sdkaws.ToString(out.FunctionName) != name {
		return FunctionConfig{}, c.outsideScope()
	}
	config := FunctionConfig{
		Name:             name,
		Runtime:          string(out.Runtime),
		PackageType:      string(out.PackageType),
		Handler:          sdkaws.ToString(out.Handler),
		MemoryMB:         int(sdkaws.ToInt32(out.MemorySize)),
		TimeoutSeconds:   int(sdkaws.ToInt32(out.Timeout)),
		State:            string(out.State),
		StateReason:      sdkaws.ToString(out.StateReason),
		LastUpdateStatus: string(out.LastUpdateStatus),
		LastModified:     sdkaws.ToString(out.LastModified),
		CodeSize:         out.CodeSize,
		Layers:           out.Layers,
		EnvironmentNames: []string{},
	}
	for _, arch := range out.Architectures {
		config.Architectures = append(config.Architectures, string(arch))
	}
	if env := out.Environment; env != nil {
		for key := range env.Variables {
			config.EnvironmentNames = append(config.EnvironmentNames, key)
		}
		slices.Sort(config.EnvironmentNames)
		config.EnvironmentError = env.Error != nil
	}
	return config, nil
}
