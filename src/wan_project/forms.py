from django import forms
from .models import WanProject


class WanModelForm(forms.ModelForm):
    class Meta:
        model = WanProject
        widgets = {
            'domain_or_ip': forms.TextInput(attrs={'placeholder': 'www.example.com'}),
        }
        fields = [
            'project_name',
            'domain_or_ip',
        ]
