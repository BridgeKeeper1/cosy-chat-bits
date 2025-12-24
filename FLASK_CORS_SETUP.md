# CORS Setup for Chatter Flask Backend

## Quick Setup

Add these lines at the TOP of your chatter2.py file (after imports):

```python
from flask_cors import CORS

# Then after creating the Flask app (app = Flask(__name__)):
CORS(app, 
     supports_credentials=True, 
     origins=[
         "http://localhost:5173",
         "http://localhost:3000",
         "https://*.lovable.app",
         "https://id-preview--ac3ced5d-316c-4391-a133-ba692d2de613.lovable.app"
     ],
     allow_headers=["Content-Type", "Authorization", "X-Client-ID", "X-DBX"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)
```

## Install flask-cors

```bash
pip install flask-cors
```

## For Socket.IO CORS

Your SocketIO initialization should look like:

```python
socketio = SocketIO(app, 
                    cors_allowed_origins=[
                        "http://localhost:5173",
                        "http://localhost:3000", 
                        "https://*.lovable.app",
                        "https://id-preview--ac3ced5d-316c-4391-a133-ba692d2de613.lovable.app"
                    ],
                    manage_session=False)
```

## Full Example

Here's where to add it in your code:

```python
# At the top with imports
from flask import Flask, request, jsonify, session, ...
from flask_cors import CORS  # ADD THIS
from flask_socketio import SocketIO, emit, join_room, leave_room

# ... other imports ...

# App initialization (find where app is created)
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# ADD CORS RIGHT AFTER APP CREATION
CORS(app, 
     supports_credentials=True, 
     origins=[
         "http://localhost:5173",
         "http://localhost:3000",
         "https://*.lovable.app",
         "https://id-preview--ac3ced5d-316c-4391-a133-ba692d2de613.lovable.app"
     ])

# Update SocketIO initialization
socketio = SocketIO(app, 
                    cors_allowed_origins=[
                        "http://localhost:5173",
                        "http://localhost:3000",
                        "https://*.lovable.app",
                        "https://id-preview--ac3ced5d-316c-4391-a133-ba692d2de613.lovable.app"  
                    ],
                    manage_session=False)
```

## Troubleshooting

1. Make sure flask-cors is installed: `pip install flask-cors`
2. Restart your Flask server after making changes
3. Clear your browser cache if issues persist
4. Check the browser console for CORS errors

## File Location

Your Flask backend file has been copied to: `public/chatter2.py`
You need to manually add the CORS configuration to your actual Flask file.
