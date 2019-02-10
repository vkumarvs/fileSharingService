'''
Write a login event to S3.
'''

import boto3
from datetime import datetime
import logging
import json
import os

# Initialize objects and set variables that are not invocation specific to
# exploit container reuse.
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.root.setLevel(logging.getLevelName(log_level))
_logger = logging.getLogger(__name__)

s3_client = boto3.client('s3')
s3_bucket = os.environ.get('S3_BUCKET_NAME')

def init(event, context):
    '''Lambda entry point.'''
    print("hello I am vipin")
    _logger.debug('Event received: {}'.format(json.dumps(event)))



'''
def _get_s3_object_key_by_event_detail(event_detail):
    '''Return S3 object key from event data detail'''
    event_date = event_detail.get('eventTime')
    event_datetime = datetime.strptime(event_date, '%Y-%m-%dT%H:%M:%SZ')
    event_id = event_detail.get('eventID')

    s3_object_key = '{datetime_year}/{datetime_month}/{datetime_day}/{event_id}.json'.format(
        datetime_year=event_datetime.year,
        datetime_month=event_datetime.month,
        datetime_day=event_datetime.day,
        event_id=event_id
    )

    return s3_object_key


def handler(event, context):
    '''Lambda entry point.'''
    _logger.debug('Event received: {}'.format(json.dumps(event)))

    # We're going to ignorethe CloudWatch event data and work with just the
    # CloudTrail data.
    event_detail = event.get('detail')

    # Get our S3 object name from the CloudTrail data
    s3_object_key = _get_s3_object_key_by_event_detail(event_detail)

    # Write the event to S3.
    s3_resp = s3_client.put_object(
        ACL='private',
        Body=json.dumps(event_detail).encode(),
        Bucket=s3_bucket,
        Key=s3_object_key
    )

    _logger.info(
        'Console login event {event_id} at {event_time} logged to: {s3_bucket}/{s3_object_key}'.format(
            event_id=event_detail.get('eventID'),
            event_time=event_detail.get('eventTime'),
            s3_bucket=s3_bucket,
            s3_object_key=s3_object_key
        )
    )
    return s3_resp
'''
