import praw
import pytz
import json
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

import boto3
import base64
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "reddit/api_secrets"
    region_name = "us-east-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return client.get_secret_value(
            SecretId=secret_name
        )


def digest_email(event=None, context=None):
    secrets = json.loads(get_secret()['SecretString'])

    reddit = praw.Reddit(
        client_id=secrets['reddit_client_id'],
        client_secret=secrets['reddit_client_secret'],
        user_agent="python:mediareader:v0.0.1 (by/BatsuGame13)",
        username=secrets['reddit_username'],
        password=secrets['reddit_password']
    )

    local_time = pytz.timezone("America/Chicago")

    subreddits = reddit.user.subreddits(limit=None)
    text_list = ['<html>', '<body>', '<p>Daily Reddit Digest</p>']
    for subreddit in subreddits:
        i = 0
        text_list.append('<p>' + subreddit.display_name.upper() + '</p>')
        for submission in subreddit.top(time_filter='day', limit = 10):
            created_at = datetime.fromtimestamp(submission.created_utc, local_time).replace(tzinfo=None)
            cutoff = datetime.now(local_time).replace(tzinfo=None) - timedelta(days=1)
            if created_at >= cutoff:
                i += 1
                submission = str(i) + '. ' + '<a href="' + submission.url + '">' + submission.title + '</a><br>'
                text_list.append(submission)
        text_list.append('')
    text_list.append('</body></html>')

    text = '\n'.join(text_list)

    message = Mail(
        from_email='pythonmediareader@gmail.com',
        to_emails='michael.g.fagan@gmail.com',
        subject='Python Media Reader Digest',
        html_content=text)
    try:
        sg = SendGridAPIClient(secrets['sendgrid_api_key'])
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception:
        return {
            'statusCode': response.status_code,
            'body': response.body
        }