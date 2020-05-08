// Copyright 2020 Antrea Authors
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

package main

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"k8s.io/klog"
)

const (
	// This address must be verified with Amazon SES.
	Sender = "antreabot@gmail.com"

	// Account is still in the sandbox, this address must be verified.
	// TODO: replace with Antrea mailing list
	Recipient = "antonin.bas@gmail.com"

	// The character encoding for the email.
	CharSet = "UTF-8"

	AWSRegion = "us-west-2"
)

func isNeeded(stats *reportStats, maxScore int, newStats *reportStats) bool {
	if stats.score > maxScore {
		return true
	}
	if stats.countHighOrHigher > 0 {
		return true
	}
	if newStats != nil && stats.score > newStats.score {
		return true
	}
	return false
}

func notifyIfNeeded(stats *reportStats, maxScore int, newStats *reportStats) error {
	if !isNeeded(stats, maxScore, newStats) {
		klog.Infof("No need to send an email notification")
		return nil
	}

	klog.Infof("Sending email to address: %s", Recipient)

	subject := fmt.Sprintf("Antrea Docker Image Security Update - %s", time.Now().Format("Mon-Jan-2"))

	// Craft email body.
	textBody := "This email is sent by the Antreabot as a result of a security scan on an Antrea Docker image.\n"
	textBody += "\n"
	textBody += "Here are the results for the tested image:\n"
	textBody += stats.PrettyString()
	textBody += "\n"
	if stats.score > maxScore {
		textBody += fmt.Sprintf("Score exceeds max value of %d.\n", maxScore)
	}
	if stats.countHighOrHigher > 0 {
		textBody += "At least one vulnerability has severity High or higher.\n"
	}
	if newStats != nil && stats.score > newStats.score {
		textBody += "Releasing a new Docker image may reduce number of vulnerabilities.\n"
		textBody += newStats.PrettyString()
	}
	textBody += "\n"

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(AWSRegion)},
	)
	if err != nil {
		return fmt.Errorf("cannot create session to AWS: %v", err)
	}

	// Create an SES session.
	svc := ses.New(sess)

	// TODO: add JSON reports as attachments. This is a more complicated API however.

	// Assemble the email.
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(Recipient),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String(CharSet),
					Data:    aws.String(textBody),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(CharSet),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(Sender),
	}

	// Attempt to send the email.
	result, err := svc.SendEmail(input)

	// Convert error
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return fmt.Errorf(aerr.Error())
		} else {
			return fmt.Errorf(err.Error())
		}
	}

	klog.Infof("Email sent to address: %s", Recipient)
	klog.Infof("Result: %v", result)

	return nil
}
