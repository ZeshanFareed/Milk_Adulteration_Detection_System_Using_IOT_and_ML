import logging
from django.shortcuts import redirect
from django.contrib import messages
from firebase_admin import auth, db
from django.conf import settings

logger = logging.getLogger(__name__)

class FirebaseAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        logger.debug(f"Middleware processing path: {request.path}, Session: {request.session.items()}")
        
        # Skip auth checks for public pages
        public_paths = ['/login/', '/signup/', ]
        if request.path in public_paths:
            request.user_role = None
            logger.debug("Public path, skipping auth check")
            return self.get_response(request)

        # Check for session uid
        uid = request.session.get('uid')
        if not uid:
            logger.error("No UID in session, redirecting to login")
            messages.error(request, 'Please log in to access this page.')
            return redirect('login')

        try:
            # Fetch user role from Firebase
            user_ref = db.reference(f'users/{uid}')
            user_data = user_ref.get()
            logger.debug(f"Fetched user data for UID {uid}: {user_data}")
            
            if not user_data:
                logger.error(f"No user data found for UID: {uid}")
                messages.error(request, 'User data not found. Please log in again.')
                request.session.flush()
                return redirect('login')

            user_role = user_data.get('role', 'user')
            logger.info(f"User role for UID {uid}: {user_role}")
            
            # Set request attributes
            request.user_role = user_role
            request.allowed_pages = settings.USER_ROLES.get(user_role, ['dashboard', 'help'])
            
            # Force sync session role
            request.session['role'] = user_role
            request.session.modified = True
            logger.info(f"Updated session role for UID {uid} to {user_role}")
            logger.debug(f"Session after update: {request.session.items()}")
                
        except Exception as e:
            logger.error(f"Error fetching user data for UID {uid}: {str(e)}")
            messages.error(request, 'Error verifying user. Please log in again.')
            request.session.flush()
            return redirect('login')

        return self.get_response(request)