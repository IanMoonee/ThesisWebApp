from django import forms
from .models import WanProject


class WanModelForm(forms.ModelForm):
    checkbox_port_choices = (('common', "scan default ports"),
                             ('wide', "wider scan(1-1024)"))

    port_options = forms.ChoiceField(label='Select what ports will be scanned', choices=checkbox_port_choices)

    class Meta:
        model = WanProject
        widgets = {
            'domain_or_ip': forms.TextInput(attrs={'placeholder': 'www.example.com'}),
        }
        fields = [
            'project_name',
            'domain_or_ip',
            'port_options',
        ]
