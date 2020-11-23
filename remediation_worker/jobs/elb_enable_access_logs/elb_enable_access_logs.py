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

import boto3
import json
import sys
import logging
logging.basicConfig(level=logging.INFO)

from botocore.exceptions import ClientError

def logcall(f, *args, **kwargs):
    logging.info('%s(%s)', f.__name__, ', '.join(list(args) + [f'{k}={repr(v)}' for k, v in kwargs.items()]))
    res = f(*args, **kwargs)
    logging.info(res)
    return res

# taken from https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html
ELB_ACCOUNT_IDS = {
    'us-east-1': '127311923021',
    'us-east-2': '033677994240',
    'us-west-1': '027434742980',
    'us-west-2': '797873946194',
    'af-south-1': '098369216593',
    'ca-central-1': '985666609251',
    'eu-central-1': '054676820928',
    'eu-west-1': '156460612806',
    'eu-west-2': '652711504416',
    'eu-south-1': '635631232127',
    'eu-west-3': '009996457667',
    'eu-north-1': '897822967062',
    'ap-east-1': '754344448648',
    'ap-northeast-1': '582318560864',
    'ap-northeast-2': '600734575887',
    'ap-northeast-3': '383597477331',
    'ap-southeast-1': '114774131450',
    'ap-southeast-2': '783225319266',
    'ap-south-1': '718504428378',
    'me-south-1': '076674570225',
    'sa-east-1': '507241528517',
    'us-gov-west-1': '048591011584',
    'us-gov-east-1': '190560391635',
    'cn-north-1': '638102146993',
    'cn-northwest-1': '037604701340'
}

def create_or_update_bucket_policy(s3_client, bucket_name, bucket_prefix, account_id, region):
    elb_account_id = ELB_ACCOUNT_IDS[region]
    statement = {
        'Effect': 'Allow',
        'Principal': {
            'AWS': f'arn:aws:iam::{elb_account_id}:root'
        },
        'Action': 's3:PutObject',
        'Resource': f'arn:aws:s3:::{bucket_name}/{bucket_prefix}/AWSLogs/{account_id}/*'
    }
    try:
        policy = json.loads(logcall(s3_client.get_bucket_policy, Bucket=bucket_name)['Policy'])
        if statement not in policy['Statement']:
            policy['Statement'].append(statement)
            logcall(
                s3_client.put_bucket_policy,
                Bucket=bucket_name,
                Policy=json.dumps(policy)
            )
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            policy = {
                'Version': '2012-10-17',
                'Statement': [
                    statement
                ]
            }
            logcall(
                s3_client.put_bucket_policy,
                Bucket=bucket_name,
                Policy=json.dumps(policy)
            )
        else:
            raise e

class ELBEnableAccessLogs(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        payload_dict = json.loads(payload)
        return {
            'elb_name': payload_dict['notificationInfo']['FindingInfo']['ObjectId'],
            'region': payload_dict['notificationInfo']['FindingInfo']['Region'],
            'cloud_account_id': payload_dict['notificationInfo']['CloudAccountId']
        }

    def ensure_log_target_bucket(self, s3_client, target_bucket, region):
        try:
            logcall(s3_client.head_bucket,
                    Bucket=target_bucket)
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                # The bucket does not exist
                if region == "us-east-1":
                    logcall(s3_client.create_bucket,
                            Bucket=target_bucket)
                else:
                    logcall(s3_client.create_bucket,
                        Bucket=target_bucket,
                        CreateBucketConfiguration={"LocationConstraint": region}
                    )
            elif e.response["Error"]["Code"] == "403":
                # The assumed role does not have the permission
                logging.error("Not enough permissions to list buckets")
                raise e
            else:
                raise e

    def remediate(self, elb_client, s3_client, elb_name, cloud_account_id, region):
        """Enables access logs for the given ELB.

        :param elb_client: AWS ELB boto3 client
        :param s3_client: AWS S3 boto3 client
        :param elb_name: Name of elastic load balancer
        :param cloud_account_id: Customer cloud account id
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        logs_enabled = logcall(elb_client.describe_load_balancer_attributes, LoadBalancerName=elb_name)['LoadBalancerAttributes']['AccessLog']['Enabled']

        if logs_enabled:
            logging.info('access logs already enabled')
        else:
            logging.info('enabling access logs')
            bucket_name = f'vss-logging-target-{cloud_account_id}-{region}'
            bucket_prefix = elb_name
            self.ensure_log_target_bucket(s3_client, bucket_name, region)
            create_or_update_bucket_policy(s3_client, bucket_name, bucket_prefix, cloud_account_id, region)
            logcall(
                elb_client.modify_load_balancer_attributes,
                LoadBalancerName=elb_name,
                LoadBalancerAttributes={
                    'AccessLog': {
                        'Enabled': True,
                        'S3BucketName': bucket_name,
                        'S3BucketPrefix': bucket_prefix
                    }
                }
            )

        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        elb_client = boto3.client('elb', region_name=params['region'])
        s3_client = boto3.client('s3', region_name=params['region'])
        return self.remediate(elb_client, s3_client, **params)


if __name__ == '__main__':
    sys.exit(ELBEnableAccessLogs().run(sys.argv))
