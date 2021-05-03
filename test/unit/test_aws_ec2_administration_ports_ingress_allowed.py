# Copyright (c) 2020 VMware Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest
from mock import Mock

from remediation_worker.jobs.aws_ec2_administration_ports_ingress_allowed.aws_ec2_administration_ports_ingress_allowed import (
    RemoveAdministrationPortsPublicAccess,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "EC2",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "network_acl_id",
            "ObjectChain": "{\\"cloudAccountId\\":\\"cloud_account_id\\",\\"entityId\\":\\"AWS.EC2.15960266902.us-west-2.Key.key_id\\",\\"entityName\\":\\"key_id\\",\\"entityType\\":\\"AWS.KMS.Key\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"156898827089\\",\\"provider\\":\\"AWS\\",\\"region\\":\\"us-west-2\\",\\"service\\":\\"CloudTrail\\", \\"properties\\":[{\\"name\\":\\"KeyState\\",\\"stringV\\":\\"Enabled\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestCloudtrailS3PublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = RemoveAdministrationPortsPublicAccess().parse(valid_payload)
        assert params["network_acl_id"] == "network_acl_id"
        assert params["cloud_account_id"] == "cloud_account_id"
        assert params["region"] == "region"

    def test_remediate_success_with_bucket_policy_public(self):
        client = Mock()
        action = RemoveAdministrationPortsPublicAccess()
        network_acls = {
            "NetworkAcls": [
                {
                    "Associations": [],
                    "Entries": [
                        {
                            "CidrBlock": "0.0.0.0/0",
                            "Egress": True,
                            "Protocol": "-1",
                            "RuleAction": "deny",
                            "RuleNumber": 32767,
                        },
                        {
                            "Egress": True,
                            "Ipv6CidrBlock": "::/0",
                            "Protocol": "-1",
                            "RuleAction": "deny",
                            "RuleNumber": 32768,
                        },
                        {
                            "CidrBlock": "0.0.0.0/0",
                            "Egress": False,
                            "PortRange": {"From": 0, "To": 65535},
                            "Protocol": "6",
                            "RuleAction": "allow",
                            "RuleNumber": 100,
                        },
                        {
                            "CidrBlock": "0.0.0.0/0",
                            "Egress": False,
                            "PortRange": {"From": 3389, "To": 3389},
                            "Protocol": "6",
                            "RuleAction": "allow",
                            "RuleNumber": 101,
                        },
                        {
                            "CidrBlock": "0.0.0.0/0",
                            "Egress": False,
                            "PortRange": {"From": 22, "To": 22},
                            "Protocol": "6",
                            "RuleAction": "allow",
                            "RuleNumber": 102,
                        },
                        {
                            "CidrBlock": "0.0.0.0/0",
                            "Egress": False,
                            "Protocol": "-1",
                            "RuleAction": "allow",
                            "RuleNumber": 103,
                        },
                        {
                            "CidrBlock": "0.0.0.0/0",
                            "Egress": False,
                            "Protocol": "-1",
                            "RuleAction": "deny",
                            "RuleNumber": 32767,
                        },
                        {
                            "Egress": False,
                            "Ipv6CidrBlock": "::/0",
                            "Protocol": "-1",
                            "RuleAction": "deny",
                            "RuleNumber": 32768,
                        },
                    ],
                    "IsDefault": False,
                    "NetworkAclId": "acl-08f735e74e7fbfc91",
                    "Tags": [{"Key": "Name", "Value": "remediation-acl"}],
                    "VpcId": "vpc-0be2d6215324",
                    "OwnerId": "129034023102",
                }
            ],
            "ResponseMetadata": {
                "RequestId": "47a06dc4-c4ed-4c44-aa75-18b48308a8a0",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amzn-requestid": "47a06dc4-c4ed-4c44-aa75-18b48308a8a0",
                    "cache-control": "no-cache, no-store",
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                    "content-type": "text/xml;charset=UTF-8",
                    "content-length": "3461",
                    "vary": "accept-encoding",
                    "date": "Wed, 24 Feb 2021 14:15:01 GMT",
                    "server": "AmazonEC2",
                },
                "RetryAttempts": 0,
            },
        }
        client.describe_network_acls.return_value = network_acls
        assert (
            action.remediate("region", client, "network_acl_id", "cloud_account_id")
            == 0
        )

    def test_remediate_with_exception(self):
        client = Mock()
        action = RemoveAdministrationPortsPublicAccess()
        with pytest.raises(Exception):
            assert action.remediate(client)
