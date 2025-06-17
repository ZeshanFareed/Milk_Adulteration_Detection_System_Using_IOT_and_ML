from django.urls import path
from .views import (
    predict_from_firebase,
    dashboard,
    reports,
    setting,
    help_page,
    user_management,
    edit_user,
    delete_user,
    signup,
    login_view,
    logout_view,
    upload_csv,
    current_report,
)

urlpatterns = [
    path('', login_view, name='login'),
    path('login/', login_view, name='login'),
    path('signup/', signup, name='signup'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard, name='dashboard'),
    path('predict/', predict_from_firebase, name='predict_from_firebase'),
    path('upload_csv/', upload_csv, name='upload_csv'),
    path('report/current/', current_report, name='current_report'),
    path('reports/', reports, name='reports'),
    path('setting/', setting, name='setting'),
    path('help/', help_page, name='help'),
    path('users/', user_management, name='user_management'),
    path('users/edit/<str:user_id>/', edit_user, name='edit_user'),
    path('users/delete/<str:user_id>/', delete_user, name='delete_user'),
]