// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func AssignIPToEC2ENI(ctx context.Context, interfaceID, ip string) error {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithEC2IMDSRegion())
	if err != nil {
		return fmt.Errorf("unable to load AWS configuration: %w", err)
	}
	client := ec2.NewFromConfig(cfg)

	ipInput := &ec2.AssignPrivateIpAddressesInput{
		AllowReassignment:  aws.Bool(true),
		NetworkInterfaceId: aws.String(interfaceID),
		PrivateIpAddresses: []string{ip},
	}
	_, err = client.AssignPrivateIpAddresses(ctx, ipInput)
	if err != nil {
		return fmt.Errorf("unable to assign IP %s to interface %s: %w", ip, interfaceID, err)
	}
	return nil
}
