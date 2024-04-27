import base64
import json
import time
from threading import Thread
import requests
from flask import Flask, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

app = Flask(__name__)

CLIENT_SECRETS_FILE = 'credentials.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly']
REDIRECT_URI = 'https://gmail-api.duckdns.org:8443/oauth2callback'
BOT_TOKEN = open('bot_token.txt').read().strip()
IP = requests.get('https://httpbin.org/get').json()['origin']
AUTHORIZED_HELP_1 = 'You are authorized.\n'
AUTHORIZED_HELP_2 = 'To send an email, use the format:\n1. Recipient email on the first line,\n2. Subject on the second line,\n3. Email body starting from the third line.\n'
NOT_AUTHORIZED_HELP_1 = 'You are not authorized.\n'
NOT_AUTHORIZED_HELP_2 = 'Please /authorize the bot to use its features.\n'

chats_credentials = {}


def get_credentials(chat_id):
    if chat_id not in chats_credentials:
        return None
    credentials = chats_credentials[chat_id]
    return Credentials(
        token=credentials['token'],
        refresh_token=credentials['refresh_token'],
        token_uri=credentials['token_uri'],
        client_id=credentials['client_id'],
        client_secret=credentials['client_secret'],
        scopes=credentials['scopes']
    )


def send_telegram_message(chat_id, text, reply_to_message_id=None):
    print(requests.get(f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage', params=dict(
        chat_id=chat_id,
        text=text,
        reply_parameters=json.dumps({'message_id': reply_to_message_id}) if reply_to_message_id else None
    )).json())


def get_message_text(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body']['data']
                text = base64.b64decode(data).decode('utf-8')
                return text
    else:
        data = payload['body']['data']
        text = base64.b64decode(data).decode('utf-8')
        return text
    return ''


def check_for_new_emails(chat_id):
    creds = get_credentials(chat_id)
    if not creds:
        return
    service = build('gmail', 'v1', credentials=creds)
    try:
        last_id = chats_credentials[chat_id].get('last_id', '')
        results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
        messages = results.get('messages', [])
        new_messages = []
        for msg in messages:
            if msg['id'] <= last_id:
                break
            new_messages.append(msg)
        if not new_messages:
            return
        chats_credentials[chat_id]['last_id'] = new_messages[0]['id']
        if not last_id:
            return
        for msg in reversed(new_messages):
            txt = service.users().messages().get(userId='me', id=msg['id']).execute()
            chats_credentials[chat_id]['last_id'] = msg['id']
            try:
                payload = txt['payload']
                headers = payload['headers']
                subject = None
                sender = None
                for header in headers:
                    if header['name'] == 'Subject':
                        subject = header['value']
                    elif header['name'] == 'From':
                        sender = header['value']
                notify_text = 'New email received.\n'
                if sender is not None:
                    notify_text += f'From: {sender}\n'
                if subject is not None:
                    notify_text += f'Subject: {subject}\n'
                notify_text += '\nContent:\n' + get_message_text(payload)
                send_telegram_message(chat_id, notify_text)
            except Exception as e:
                print(f"Failed to process email: {repr(e)}")
    except HttpError as error:
        print(f"Failed to check emails: {repr(error)}")


def listen_for_new_emails():
    while True:
        for chat_id in chats_credentials:
            check_for_new_emails(chat_id)
        time.sleep(1)


@app.route('/oauth2callback')
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    chats_credentials[request.args['state']] = {
        'token': flow.credentials.token,
        'refresh_token': flow.credentials.refresh_token,
        'token_uri': flow.credentials.token_uri,
        'client_id': flow.credentials.client_id,
        'client_secret': flow.credentials.client_secret,
        'scopes': flow.credentials.scopes
    }
    chat_id = request.args['state']
    send_telegram_message(chat_id, 'Authorization completed successfully.\n' + AUTHORIZED_HELP_2)
    check_for_new_emails(chat_id)
    return 'Authorization is completed. You can return to Telegram.'


@app.route('/telegram', methods=['POST'])
def telegram():
    update = request.get_json()
    print(update)
    if 'message' not in update:
        return ''
    message = update['message']
    message_id = message['message_id']
    chat = message['chat']
    chat_id = str(chat['id'])
    if 'text' not in message:
        return ''
    text = message['text']
    reply = lambda reply_text: send_telegram_message(chat_id, reply_text, message_id)
    if text in ['/start', '/authorize']:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI, state=chat_id)
        authorization_url, state = flow.authorization_url(
            access_type='offline', include_granted_scopes='true')
        reply(f'Use the following link to authorize: {authorization_url}')
    elif text == '/revoke':
        if chat_id in chats_credentials:
            del chats_credentials[chat_id]
            reply('Access has been revoked successfully.\n' + NOT_AUTHORIZED_HELP_2)
        else:
            reply(NOT_AUTHORIZED_HELP_1 + NOT_AUTHORIZED_HELP_2)
    elif text == '/status':
        if chat_id in chats_credentials:
            reply(AUTHORIZED_HELP_1 + AUTHORIZED_HELP_2)
        else:
            reply(NOT_AUTHORIZED_HELP_1 + NOT_AUTHORIZED_HELP_2)
    else:
        lines = text.split('\n', 2)
        if chat_id not in chats_credentials:
            reply(NOT_AUTHORIZED_HELP_1 + NOT_AUTHORIZED_HELP_2)
        elif len(lines) != 3:
            reply('Invalid format.\n' + AUTHORIZED_HELP_2)
        else:
            recipient, subject, content = lines
            try:
                creds = get_credentials(chat_id)
                service = build('gmail', 'v1', credentials=creds)
                message = (f"From: 'me'\n"
                           f"To: {recipient}\n"
                           f"Subject: {subject}\n\n"
                           f"{content}")
                encoded_message = {'raw': base64.urlsafe_b64encode(message.encode("utf-8")).decode("ascii")}
                service.users().messages().send(userId='me', body=encoded_message).execute()
                reply('Email has been sent successfully.')
            except HttpError as error:
                reply(f'Failed to send email: {repr(error)}')
    return ''


print(requests.get(f'https://api.telegram.org/bot{BOT_TOKEN}/setWebhook', params=dict(
    url='https://gmail-api.duckdns.org:8443/telegram',
    drop_pending_updates=True,
    ip_address=IP,
    allowed_updates=['message']
)).json())

listener_thread = Thread(target=listen_for_new_emails)
listener_thread.start()

app.run('0.0.0.0', 8443, ssl_context=(
    '/etc/letsencrypt/live/gmail-api.duckdns.org/fullchain.pem',
    '/etc/letsencrypt/live/gmail-api.duckdns.org/privkey.pem'
))
