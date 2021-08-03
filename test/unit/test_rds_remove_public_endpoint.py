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
#from botocore.exceptions import ClientError

from remediation_worker.jobs.rds_remove_public_endpoint.rds_remove_public_endpoint import RDSRemovePublicEndpoint

@pytest.fixture
def valid_payload():
    return """ {
    "notificationInfo": {
        "FindingInfo": {
            "ObjectId": "i-00347a2be30cf1a15",
            "Region": "us-east-1"
        }
    }
  }
"""


class TestRDSRemovePublicEndpoint:
    def test_parse_payload(self, valid_payload):
        obj = RDSRemovePublicEndpoint()
        param = obj.parse(valid_payload)
        assert "instance_id" in param
        assert param["instance_id"] == "i-00347a2be30cf1a15"
        assert "region" in param
        assert param["region"] == "us-east-1"


    def test_remediation_success(self, valid_payload):
        class TestClient(object):
            def modify_db_instance(self, **kwargs):
                return 1

            def describe_db_instances(self, **kwargs):
                rds = {'DBInstances':[{'PubliclyAccessible':True}]}
                return rds

        client = TestClient()
        obj = RDSRemovePublicEndpoint()
        assert obj.remediate(client, "database-1") == 0

    def test_remediation_not_success(self, valid_payload):
        class TestClient(object):
            def modify_db_instance(self, **kwargs):
                raise ClientError(
                   {
                        "Error": {
                            "Code": "InvalidDBInstanceState",
                            "Message": "InvalidDBInstanceState msg",
                        }
                    },
                    "InvalidDBInstance",
                )

            def describe_db_instances(self, **kwargs):
                rds = {'DBInstances':[{'PubliclyAccessible':True}]}
                return rds
                

        client = TestClient()
        obj = RDSRemovePublicEndpoint()
        assert obj.remediate(client, "database-1") == 1
    
    