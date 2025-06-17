# forms.py
from django import forms

class ReportForm(forms.Form):
    start_date = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        required=False,
        label="Start Date"
    )
    end_date = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        required=False,
        label="End Date"
    )
    search_query = forms.CharField(
        max_length=100,
        required=False,
        label="Search Predictions",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Search by prediction (e.g., Pure Milk)'})
    )