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
	"bytes"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"gopkg.in/gomail.v2"
	"k8s.io/klog/v2"
)

const (
	// This address must be verified with Amazon SES.
	Sender = "antreabot@gmail.com"

	// The character encoding for the email.
	CharSet = "UTF-8"

	AWSRegion = "us-west-2"
)

var Recipients = []string{
	"projectantrea-dev@googlegroups.com",
	"projectantrea-maintainers@googlegroups.com",
}

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

func notifyIfNeeded(
	stats *reportStats,
	maxScore int,
	newStats *reportStats,
	reportPath string,
	newReportPath string,
) error {
	if !isNeeded(stats, maxScore, newStats) {
		klog.Infof("No need to send an email notification")
		return nil
	}

	klog.Infof("Sending email to addresses: %v", Recipients)

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

	// Assemble the email.
	msg := gomail.NewMessage(gomail.SetCharset(CharSet))
	msg.SetHeader("From", Sender)
	msg.SetHeader("To", Recipients...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", textBody)
	// Attach JSON reports to email.
	msg.Attach(reportPath)
	if newReportPath != "" {
		msg.Attach(newReportPath)
	}

	var emailRaw bytes.Buffer
	msg.WriteTo(&emailRaw)

	message := ses.RawMessage{Data: emailRaw.Bytes()}
	// Other fields are not required.
	input := &ses.SendRawEmailInput{RawMessage: &message}

	// Attempt to send the email.
	result, err := svc.SendRawEmail(input)

	// Convert error
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return fmt.Errorf(aerr.Error())
		} else {
			return fmt.Errorf(err.Error())
		}
	}

	klog.Infof("Email sent to addresses: %v", Recipients)
	klog.Infof("Result: %v", result)

	return nil
}
