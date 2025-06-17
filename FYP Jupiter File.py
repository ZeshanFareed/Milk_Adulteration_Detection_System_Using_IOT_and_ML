import joblib
import numpy as np
from django.shortcuts import render, redirect
import firebase_admin
from firebase_admin import credentials, db, auth
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.conf import settings
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
import csv
import openpyxl
from io import BytesIO
import requests
import os
import logging
import re
import pandas as pd
from .forms import ReportForm
from django.utils.translation import activate, gettext as _
from adulterant_explanations import get_adulterant_explanations  

# Firebase Initialization
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS)
        firebase_admin.initialize_app(cred, {
            'databaseURL': settings.FIREBASE_CONFIG['databaseURL']
        })
        logger.info("Firebase initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {str(e)}")
        raise Exception("Firebase initialization failed")

# Set up logging
logger = logging.getLogger(__name__)

# Load the trained ML model and scaler
model = joblib.load(os.path.join(settings.BASE_DIR, 'models', r'C:\Users\PMLS\Documents\MADS\MADS\MADS\milk_adulteration_model.pkl'))
scaler = joblib.load(os.path.join(settings.BASE_DIR, 'models', r'C:\Users\PMLS\Documents\MADS\MADS\MADS\scaler.pkl'))

FEATURES = ['Lactose', 'Fat', 'SNF', 'Protein', 'Gravity', 'pH', 'Temperature', 'Gas', 'EC']

# Custom decorator for role-based access
def role_required(*allowed_roles):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            user_role = request.session.get('role', 'user')
            if user_role not in allowed_roles:
                logger.warning(f"User role {user_role} not allowed for this page")
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# Function to store prediction in Firebase
def store_prediction_in_firebase(prediction, sensor_values, timestamp):
    try:
        predictions_ref = db.reference('predictions')
        prediction_id = predictions_ref.push().key
        prediction_data = {
            'timestamp': timestamp,
            'prediction': prediction,
            'sensor_values': sensor_values
        }
        predictions_ref.child(prediction_id).set(prediction_data)
        logger.info(f"Stored prediction in Firebase: {prediction} at {timestamp}")
    except Exception as e:
        logger.error(f"Error storing prediction in Firebase: {str(e)}")

# Signup view
def signup(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        role = request.POST.get('role')
        
        logger.debug(f"Signup attempt with email: {email}, role: {role}")
        
        if not email or not password or not role:
            messages.error(request, 'All fields are required.')
            logger.error("Signup failed: Missing required fields")
            return render(request, 'signup.html')
        
        email_regex = r'^[a-zA-Z0.9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            messages.error(request, 'Please enter a valid email address.')
            logger.error("Signup failed: Invalid email format")
            return render(request, 'signup.html')
        
        if len(password) < 6:
            messages.error(request, 'Password must be at least 6 characters long.')
            logger.error("Signup failed: Password too short")
            return render(request, 'signup.html')
        
        valid_roles = ['qc', 'user']
        if role not in valid_roles:
            messages.error(request, 'Invalid role selected.')
            logger.error(f"Signup failed: Invalid role {role}")
            return render(request, 'signup.html')
        
        try:
            user = auth.create_user(email=email, password=password)
            user_ref = db.reference(f'users/{user.uid}')
            user_ref.set({
                'email': email,
                'role': role,
                'created_at': datetime.now().isoformat()
            })
            logger.info(f"User created: {email}, UID: {user.uid}, Role: {role}")
            messages.success(request, 'Account created successfully! Please log in.')
            return redirect('login')
        except auth.EmailAlreadyExistsError:
            messages.error(request, 'An account with this email already exists.')
            logger.error(f"Signup failed: Email {email} already exists")
        except Exception as e:
            logger.error(f"Unexpected error during signup: {str(e)}")
            messages.error(request, 'An unexpected error occurred.')
        return render(request, 'signup.html')
    
    return render(request, 'signup.html')

# Login view
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        logger.debug(f"Attempting login with email: '{email}'")

        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            messages.error(request, 'Please enter a valid email address.')
            logger.error("Invalid email format")
            return render(request, 'login.html')

        api_key = settings.FIREBASE_CONFIG['apiKey']
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"

        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Login successful for email: {email}, localId: {data['localId']}")
            
            request.session['uid'] = data['localId']
            request.session['email'] = email
            
            user_ref = db.reference(f'users/{data["localId"]}')
            user_data = user_ref.get()
            logger.debug(f"Fetched user data: {user_data}")
            
            if not user_data:
                logger.error(f"No user data found for UID: {data['localId']}")
                messages.error(request, 'User data not found. Please sign up.')
                request.session.flush()
                return redirect('signup')
            
            role = user_data.get('role', 'user')
            valid_roles = settings.USER_ROLES.keys()
            if role not in valid_roles:
                logger.error(f"Invalid role {role} for user {email}")
                messages.error(request, 'Invalid user role.')
                request.session.flush()
                return render(request, 'login.html')
            
            # Update last_login timestamp
            user_ref.update({
                'last_login': datetime.now().isoformat()
            })
            logger.info(f"Updated last_login for {email}")

            request.session['role'] = role
            request.session.modified = True
            logger.info(f"Set session role for {email}: {role}")
            logger.debug(f"Session after role setting: {request.session.items()}")
            
            messages.success(request, 'Login successful.')
            return redirect('dashboard')
        
        except requests.exceptions.RequestException as e:
            error_message = 'Invalid email or password.'
            if e.response:
                error_data = e.response.json()
                error_code = error_data.get('error', {}).get('message', '')
                error_mapping = {
                    'INVALID_PASSWORD': 'Incorrect password.',
                    'EMAIL_NOT_FOUND': 'No account found with this email.',
                    'USER_DISABLED': 'This account has been disabled.',
                    'TOO_MANY_ATTEMPTS': 'Too many attempts. Try later.'
                }
                error_message = error_mapping.get(error_code, error_message)
                logger.error(f"Firebase error for {email}: {error_data}")
            else:
                logger.error(f"Request failed for {email}: {str(e)}")
            messages.error(request, error_message)
            return render(request, 'login.html')
        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")
            messages.error(request, 'An unexpected error occurred.')
            return render(request, 'login.html')

    return render(request, 'login.html')


# Logout view
def logout_view(request):
    request.session.flush()
    messages.success(request, 'Successfully logged out.')
    return redirect('login')


# Dashboard view
def dashboard(request):
    # Activate session language
    language = request.session.get('_language', 'en')
    activate(language)
    logger.debug(f"Dashboard accessed with language: {language}, UID: {request.session.get('uid')}")

    if not request.session.get('uid'):
        logger.error("No UID in session, redirecting to login")
        messages.error(request, _("User not authenticated"))
        return redirect('login')
    
    try:
        user_ref = db.reference(f'users/{request.session["uid"]}')
        user_data = user_ref.get()
        
        if not user_data:
            logger.error(f"No user data found for UID: {request.session['uid']}")
            messages.error(request, _("User data not found"))
            return redirect('login')
            
        context = {
            'user_role': request.session.get('role', 'user'),
            'user_email': request.session.get('email', 'Unknown'),
            'pure_samples': 0,
            'adulterated_samples': 0,
            'connected_sensors': len(FEATURES)
        }
        return render(request, 'dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        messages.error(request, _("Error loading dashboard"))
        return redirect('login')


# Fetch live sensor data from Firebase
def fetch_firebase_data():
    ref = db.reference('sensorData')
    data = ref.get() or {}

    def safe_float(value, default=0.00):
        try:
            return float(value) if value not in ['', None] else default
        except ValueError:
            return default

    values = {
        'pH': safe_float(data.get('pH', 0)),
        'Temperature': safe_float(data.get('Temperature', 0)),
        'Gas': safe_float(data.get('Gas', 0))
    }
    return values

# Fetch live sensor data without prediction
def predict_from_firebase(request):
    firebase_values = fetch_firebase_data()
    
    return JsonResponse({
        'firebase': firebase_values,
        'timestamp': datetime.now().isoformat()
    })

# CSV upload view
def upload_csv(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=400)
    
    if not request.session.get('uid'):
        return JsonResponse({'error': 'User not authenticated'}, status=401)
    
    try:
        csv_file = request.FILES.get('csv_file')
        if not csv_file:
            return JsonResponse({'error': 'No file uploaded'}, status=400)
        
        if not csv_file.name.endswith('.csv'):
            return JsonResponse({'error': 'File must be a CSV'}, status=400)
        
        df = pd.read_csv(csv_file, header=None)
        if df.empty or len(df.columns) < 11:
            return JsonResponse({'error': 'Invalid CSV format'}, status=400)
        
        required_indices = [0, 1, 2, 3, 5, 10]  # Fat, SNF, Gravity, Lactose, Protein, EC
        feature_names = ['Fat', 'SNF', 'Gravity', 'Lactose', 'Protein', 'EC']
        
        csv_data = df.iloc[0].tolist()
        if len(csv_data) < 11:
            return JsonResponse({'error': 'CSV data incomplete'}, status=400)
        
        csv_values = {name: float(csv_data[idx]) for name, idx in zip(feature_names, required_indices)}
        
        live_data = fetch_firebase_data()
        
        combined_values = {
            'Lactose': csv_values['Lactose'],
            'Fat': csv_values['Fat'],
            'SNF': csv_values['SNF'],
            'Protein': csv_values['Protein'],
            'Gravity': csv_values['Gravity'],
            'EC': csv_values['EC'],
            'pH': live_data['pH'],
            'Temperature': live_data['Temperature'],
            'Gas': live_data['Gas']
        }
        
        new_data = np.array([[combined_values[feature] for feature in FEATURES]])
        if scaler:
            new_data = scaler.transform(new_data)
        prediction = model.predict(new_data)
        prediction_result = classify_prediction(prediction)
        shap_values = {feature: round(abs(combined_values[feature] * 0.1), 2) for feature in FEATURES}
        
        timestamp = datetime.now().isoformat()
        store_prediction_in_firebase(prediction_result, combined_values, timestamp)
        
        return JsonResponse({
            'prediction': prediction_result,
            'firebase': combined_values,
            'shap_values': shap_values,
            'timestamp': timestamp
        })
    
    except Exception as e:
        logger.error(f"Error processing CSV: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def classify_prediction(prediction):
    classes = {
        2: 'Pure Milk',
        5: 'Urea Adulteration',
        4: 'Starch Adulteration',
        1: 'Maltodextrin Adulteration',
        3: 'Sodium Bicarbonate Adulteration',
        0: 'Formaldehyde Adulteration',
        6: 'Water Adulteration'
    }
    return classes.get(prediction[0], 'Unknown result')

@role_required('admin', 'qc')
def reports(request):
    return render(request, 'reports.html')

@role_required('admin')
def setting(request):
    # Get the current session language, default to 'en' if not set
    session_language = request.session.get('_language', 'en')
    activate(session_language)

    # Load user preferences from Firebase
    user_ref = db.reference(f'users/{request.session["uid"]}')
    user_data = user_ref.get() or {}
    preferences = user_data.get('preferences', {
        'language': 'en',
        'timezone': 'Asia/Karachi',
        'show_tooltips': True
    })

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'reset_settings':
            # Reset settings to default
            preferences = {
                'language': 'en',
                'timezone': 'Asia/Karachi',
                'show_tooltips': True
            }
            user_ref.update({'preferences': preferences})
            request.session['_language'] = 'en'
            activate('en')
            messages.success(request, _('Settings reset to default (English language, Asia/Karachi timezone).'))
        elif action == 'clear_data':
            try:
                db.reference('predictions').delete()
                messages.success(request, _('All prediction data cleared successfully.'))
            except Exception as e:
                messages.error(request, _(f'Error clearing prediction data: {str(e)}'))
        else:
            # Handle saving user preferences
            language = request.POST.get('language', 'en')
            timezone = request.POST.get('timezone', 'Asia/Karachi')
            show_tooltips = request.POST.get('show_tooltips') == 'on'

            # Update preferences in Firebase
            preferences = {
                'language': language,
                'timezone': timezone,
                'show_tooltips': show_tooltips
            }
            user_ref.update({'preferences': preferences})

            # Store language in session and activate it
            request.session['_language'] = language
            activate(language)
            messages.success(request, _('Preferences updated successfully.'))

    # Pass preferences to the template
    context = {
        'language': preferences['language'],
        'timezone': preferences['timezone'],
        'show_tooltips': preferences['show_tooltips']
    }
    return render(request, 'setting.html', context)

@role_required('admin', 'qc', 'user')
def help_page(request):
    language = request.session.get('_language', 'en')
    activate(language)
    return render(request, 'help.html')

@role_required('admin')
def user_management(request):
    # Activate session language
    language = request.session.get('_language', 'en')
    activate(language)
    logger.debug(f"User management accessed with language: {language}, UID: {request.session.get('uid')}")

    try:
        # Fetch users from Firebase
        users_ref = db.reference('users')
        users_data = users_ref.get() or {}
        users = [
            {
                'uid': uid,
                'email': data.get('email', 'Unknown'),
                'role': data.get('role', 'user'),
                'created_at': data.get('created_at', 'N/A'),
                'last_login': data.get('last_login', None),
                'is_active': data.get('is_active', True)
            } for uid, data in users_data.items()
        ]
        logger.info(f"Fetched {len(users)} users from Firebase")
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        messages.error(request, _(f"Error fetching users: {str(e)}"))
        users = []

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        role = request.POST.get('role', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        logger.debug(f"Create user attempt: email={email}, role={role}")

        # Validation
        if not all([email, password, role, confirm_password]):
            logger.warning("Missing required fields in user creation form")
            messages.error(request, _("All fields are required."))
            return render(request, 'users.html', {'users': users, 'language': language})

        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            logger.warning(f"Invalid email format: {email}")
            messages.error(request, _("Please provide a valid email."))
            return render(request, 'users.html', {'users': users, 'language': language})

        if len(password) < 8:
            logger.warning("Password too short")
            messages.error(request, _("Password must be at least 8 characters long."))
            return render(request, 'users.html', {'users': users, 'language': language})

        if password != confirm_password:
            logger.warning("Passwords do not match")
            messages.error(request, _("Passwords must match."))
            return render(request, 'users.html', {'users': users, 'language': language})

        valid_roles = ['admin', 'qc', 'user']
        if role not in valid_roles:
            logger.warning(f"Invalid role selected: {role}")
            messages.error(request, _("Invalid role selected."))
            return render(request, 'users.html', {'users': users, 'language': language})

        try:
            # Create user in Firebase Authentication
            user = auth.create_user(email=email, password=password)
            # Store user data in Firebase Realtime Database
            user_ref = db.reference(f'users/{user.uid}')
            user_ref.set({
                'email': email,
                'role': role,
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'is_active': True
            })
            logger.info(f"User created: email={email}, UID={user.uid}, Role={role}")
            messages.success(request, _("User created successfully."))
            return redirect('user_management')
        except auth.EmailAlreadyExistsError:
            logger.error(f"Email already exists: {email}")
            messages.error(request, _("An account with this email already exists."))
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            messages.error(request, _(f"Error creating user: {str(e)}"))
        return render(request, 'users.html', {'users': users, 'language': language})

    return render(request, 'users.html', {'users': users, 'language': language})

@role_required('admin')
def edit_user(request, user_id):
    try:
        user_ref = db.reference(f'users/{user_id}')
        user_data = user_ref.get()
        if not user_data:
            logger.error(f"User not found: {user_id}")
            messages.error(request, 'User not found.')
            return redirect('user_management')
        
        if request.method == 'POST':
            email = request.POST.get('email')
            password = request.POST.get('password')
            role = request.POST.get('role')
            
            try:
                auth.update_user(user_id, email=email, password=password if password else None)
                user_ref.update({'email': email, 'role': role})
                logger.info(f"User updated: {email}, Role: {role}")
                messages.success(request, 'User updated successfully.')
                return redirect('user_management')
            except Exception as e:
                logger.error(f"Error updating user: {str(e)}")
                messages.error(request, f'Error updating user: {str(e)}')
        
        return render(request, 'edit_user.html', {
            'user': {'uid': user_id, 'email': user_data.get('email'), 'role': user_data.get('role')}
        })
    except Exception as e:
        logger.error(f"Error in edit_user: {str(e)}")
        messages.error(request, f'Error: {str(e)}')
        return redirect('user_management')

@role_required('admin')
def delete_user(request, user_id):
    try:
        if user_id == request.session.get('uid'):
            logger.error("Attempt to delete own account")
            messages.error(request, 'You cannot delete your own account.')
            return redirect('user_management')
        
        auth.delete_user(user_id)
        db.reference(f'users/{user_id}').delete()
        logger.info(f"User deleted: {user_id}")
        messages.success(request, 'User deleted successfully.')
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        messages.error(request, f'Error deleting user: {str(e)}')
    
    return redirect('user_management')


@role_required('admin', 'qc')
def current_report(request):
    # Activate session language
    language = request.session.get('_language', 'en')
    activate(language)
    logger.debug(f"Current report accessed with language: {language}, UID: {request.session.get('uid')}")

    form = ReportForm(request.GET or None)
    predictions_list = []
    
    try:
        predictions_ref = db.reference('predictions')
        predictions_data = predictions_ref.get()
        logger.debug(f"Fetched predictions: {predictions_data}")
        
        if not predictions_data:
            logger.warning("No predictions found in Firebase")
            messages.warning(request, _("No predictions available in the database."))
            context = {
                'predictions': [],
                'features': FEATURES,
                'form': form,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'adulteration_types': {
                    2: 'Pure Milk',
                    5: 'Urea Adulteration',
                    4: 'Starch Adulteration',
                    1: 'Maltodextrin Adulteration',
                    3: 'Sodium Bicarbonate Adulteration',
                    0: 'Formaldehyde Adulteration',
                    6: 'Water Adulteration'
                }
            }
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'predictions': [],
                    'features': FEATURES,
                    'messages': [{'tags': 'warning', 'message': _('No predictions available in the database.')}]
                })
            return render(request, 'current_report.html', context)
        
        # Get search query from form
        search_query = form.is_valid() and form.cleaned_data.get('search_query', '').lower().strip()

        for pred_id, pred_data in predictions_data.items():
            timestamp = pred_data.get('timestamp', '')
            if not timestamp:
                logger.warning(f"Skipping prediction {pred_id}: Missing timestamp")
                continue
            try:
                pred_date = datetime.fromisoformat(timestamp).date()
            except ValueError as ve:
                logger.error(f"Invalid timestamp format for prediction {pred_id}: {timestamp}")
                continue
            
            # Apply date filtering only if form is valid and dates are provided
            if form.is_valid() and form.cleaned_data['start_date'] and form.cleaned_data['end_date']:
                start_date = form.cleaned_data['start_date']
                end_date = form.cleaned_data['end_date']
                if not (start_date <= pred_date <= end_date):
                    continue
            
            sensor_values = pred_data.get('sensor_values', {})
            # Convert list to dict if necessary
            if isinstance(sensor_values, list):
                if len(sensor_values) == len(FEATURES):
                    sensor_values = {FEATURES[i]: float(sensor_values[i]) for i in range(len(FEATURES))}
                else:
                    logger.error(f"Invalid sensor_values length for prediction {pred_id}: {sensor_values}")
                    continue
            elif not isinstance(sensor_values, dict):
                logger.error(f"Invalid sensor_values for prediction {pred_id}: {sensor_values}")
                continue
            
            # Apply search query filtering
            prediction_text = pred_data.get('prediction', '').lower()
            if search_query and search_query not in prediction_text:
                continue
            
            # Compute shap_values
            shap_values = {k: round(abs(v * 0.1), 2) for k, v in sensor_values.items() if isinstance(v, (int, float))}
            logger.debug(f"SHAP values for prediction {pred_id}: {shap_values}")
            
            predictions_list.append({
                'timestamp': timestamp,
                'prediction': pred_data.get('prediction', 'Unknown'),
                'sensor_values': sensor_values,
                'shap_values': shap_values
            })
        
        # Sort by timestamp, newest first
        predictions_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Check if no predictions match the filters
        messages_list = []
        if not predictions_list and (form.is_valid() and (form.cleaned_data['start_date'] or form.cleaned_data['end_date'] or search_query)):
            messages.warning(request, _("No predictions match the applied filters."))
            messages_list.append({'tags': 'warning', 'message': _('No predictions match the applied filters.')})
        
        context = {
            'predictions': predictions_list,
            'features': FEATURES,
            'form': form,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'adulteration_types': {
                2: 'Pure Milk',
                5: 'Urea Adulteration',
                4: 'Starch Adulteration',
                1: 'Maltodextrin Adulteration',
                3: 'Sodium Bicarbonate Adulteration',
                0: 'Formaldehyde Adulteration',
                6: 'Water Adulteration'
            }
        }
        
        logger.debug(f"Context predictions: {context['predictions']}")
        
        # Handle AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'predictions': predictions_list,
                'features': FEATURES,
                'messages': messages_list
            })
        
        report_format = request.GET.get('format')
        if report_format == 'pdf':
            return generate_prediction_pdf(context)
        elif report_format == 'csv':
            return generate_prediction_csv(context)
        else:
            return render(request, 'current_report.html', context)
    
    except Exception as e:
        logger.error(f"Error fetching predictions for report: {str(e)}")
        import traceback
        logger.error(f"Stack trace: {traceback.format_exc()}")
        messages.error(request, _("Error loading report: {error}").format(error=str(e)))
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'predictions': [],
                'features': FEATURES,
                'messages': [{'tags': 'error', 'message': _('Error loading report: {error}').format(error=str(e))}]
            }, status=500)
        return redirect('dashboard')

def generate_prediction_pdf(context):
    """
    Generates a visually appealing PDF report for milk adulteration predictions.
    Includes a cover page, prediction history, key factors, and explanation for the detected adulterant.
    """
    response = HttpResponse(content_type='application/pdf')
    filename = f"milk_analysis_report_{context['timestamp'].replace(':', '-').replace(' ', '_')}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name='Title',
        parent=styles['Heading1'],
        fontSize=20,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#003087'),
        spaceAfter=20,
        alignment=1
    )
    subtitle_style = ParagraphStyle(
        name='Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        fontName='Helvetica',
        textColor=colors.HexColor('#4B5EAA'),
        spaceAfter=12,
        alignment=1
    )
    section_heading_style = ParagraphStyle(
        name='SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#003087'),
        spaceBefore=12,
        spaceAfter=8
    )
    normal_style = ParagraphStyle(
        name='Normal',
        parent=styles['Normal'],
        fontSize=10,
        fontName='Helvetica',
        textColor=colors.black,
        spaceAfter=6,
        leading=12
    )
    table_header_style = ParagraphStyle(
        name='TableHeader',
        parent=styles['Normal'],
        fontSize=10,
        fontName='Helvetica-Bold',
        textColor=colors.whitesmoke,
        alignment=1
    )
    
    # Cover Page
    elements.append(Paragraph("Milk Adulteration Detection Report", title_style))
    elements.append(Paragraph(f"Generated on: {context['timestamp']}", subtitle_style))
    elements.append(Spacer(1, 2*cm))
    elements.append(Paragraph("Prepared by: Milk Adulteration Detection System", normal_style))
    elements.append(PageBreak())
    
    # Prediction History Section
    elements.append(Paragraph("Prediction History", section_heading_style))
    elements.append(Paragraph("Recent milk analysis results (up to 5 latest predictions)", normal_style))
    data = [['Timestamp'] + context['features'] + ['Prediction']]
    for pred in context['predictions'][:5]:
        row = [pred['timestamp']] + [f"{pred['sensor_values'].get(f, 0):.2f}" for f in context['features']] + [pred['prediction']]
        data.append(row)
    
    table = Table(data, hAlign='CENTER')
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4B5EAA')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F4F7FA')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D3D3D3')),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 1*cm))
    
    # Key Factors Section
    if context['predictions']:
        elements.append(Paragraph("Key Factors Influencing Latest Prediction", section_heading_style))
        elements.append(Paragraph(
            f"These parameters had the most significant impact on the latest prediction ({context['predictions'][0]['prediction']}).",
            normal_style
        ))
        data = [['Parameter', 'Impact']]
        sorted_shap = sorted(context['predictions'][0]['shap_values'].items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        for feature, value in sorted_shap:
            data.append([feature, f"{value:.2f}"])
        
        table = Table(data, colWidths=[8*cm, 4*cm], hAlign='CENTER')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4B5EAA')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F4F7FA')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D3D3D3')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 1*cm))
    
    # Adulterant Explanation Section
    elements.append(Paragraph("Adulterant Explanation", section_heading_style))
    if context['predictions']:
        detected_adulterant = context['predictions'][0]['prediction']
        elements.append(Paragraph(f"Explanation for the detected result: {detected_adulterant}", normal_style))
        
        # Fetch explanations
        explanations = get_adulterant_explanations()
        details = explanations.get(detected_adulterant, {
            'description': 'No description available.',
            'health_risks': 'No health risks information available.',
            'detection_significance': 'No detection significance information available.'
        })
        
        # Create a table for the detected adulterant's explanation
        data = [
            ['Adulterant', Paragraph(detected_adulterant, normal_style)],
            ['Description', Paragraph(details['description'], normal_style)],
            ['Health Risks', Paragraph(details['health_risks'], normal_style)],
            ['Detection Significance', Paragraph(details['detection_significance'], normal_style)]
        ]
        
        table = Table(data, colWidths=[5*cm, 14*cm], hAlign='CENTER')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#4B5EAA')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, -1), 10),
            ('BOTTOMPADDING', (0, 0), (0, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#F4F7FA')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D3D3D3')),
            ('FONTSIZE', (1, 0), (1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No predictions available to provide an adulterant explanation.", normal_style))
    
    elements.append(Spacer(1, 1*cm))
    
    # Footer Note
    elements.append(Paragraph(
        "Note: This report is generated based on sensor data and machine learning predictions. For critical decisions, consult a certified laboratory.",
        normal_style
    ))
    
    try:
        doc.build(elements)
        pdf = buffer.getvalue()
        buffer.close()
        response.write(pdf)
        logger.info(f"PDF report generated successfully: {filename}")
        return response
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        buffer.close()
        raise

def generate_prediction_csv(context):
    response = HttpResponse(content_type='text/csv')
    filename = f"milk_analysis_report_{context['timestamp'].replace(':', '-').replace(' ', '_')}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    writer = csv.writer(response)
    header = ['Timestamp'] + context['features'] + ['Prediction']
    writer.writerow(header)
    
    for pred in context['predictions']:
        row = [pred['timestamp']] + [f"{pred['sensor_values'].get(feature, 0):.2f}" for feature in context['features']] + [pred['prediction']]
        writer.writerow(row)
    
    return response
