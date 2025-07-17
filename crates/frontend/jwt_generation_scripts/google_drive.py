from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import base64

"""
To use this script you need to setup a google cloud project, enable google drive api,
create a client_secrets.json file, download client_secrets.json file to this directory,
and add your email address as a test user to the google cloud project so that google
drive knows you are allowed to upload files.
"""

def get_jwt_from_google_drive():
    # 1. Authenticate and get credentials
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/drive.file']  # Allows file write
    )
    creds = flow.run_local_server(port=0)

    return creds


def decode_base64_to_ascii(encoded_str):
     """Simple base64 to ASCII conversion"""
     # Add padding if needed
     padding = 4 - (len(encoded_str) % 4)
     if padding != 4:
         encoded_str += '=' * padding

     # Replace URL-safe characters
     encoded_str = encoded_str.replace('-', '+').replace('_', '/')

     # Decode to bytes then to ASCII
     decoded_bytes = base64.b64decode(encoded_str)
     return decoded_bytes.decode('ascii', errors='replace')
                                                               
def parse_jwt(creds):
    
    print()
    print("JWT Expires: ", creds.expiry)
    print()
    print("Base64 JWT: ", creds.token)
    print()
    print("Base64 decoded JWT: ", decode_base64_to_ascii(creds.token))


def upload_file(creds, file_path="test_upload.txt"):
    
    # 2. Build the Drive service
    drive_service = build('drive', 'v3', credentials=creds)

    # 3. Create a file upload request
    file_metadata = {'name': 'test_upload.txt'}
    media = MediaFileUpload('test_upload.txt', mimetype='text/plain')

    file = drive_service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()

    print(f"✅ File uploaded successfully, ID: {file.get('id')}")


if __name__ == "__main__":
    creds = get_jwt_from_google_drive()
    parse_jwt(creds)
    upload_file(creds)
