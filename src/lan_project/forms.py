from django import forms
from .models import UserProject
# Form helper allows us to control what is displayed by crispy forms
from crispy_forms.helper import FormHelper


# Model Form is a form that is bound(connected) to a model.
# a modelForm knows where to store that data .
class LanModelForm(forms.ModelForm):
    checkbox_port_choices = (('common', "Scan only common ports."),
                             ('all', "Thorough scan."))

    port_options = forms.ChoiceField(label='Select what ports will be scanned', choices=checkbox_port_choices)
    update_db_option = forms.BooleanField(label='Update the database??', required=False)

    class Meta:
        model = UserProject
        widgets = {
            'subnet': forms.TextInput(attrs={'placeholder': '192.168.1.0/24'}),
        }
        fields = ['project_name',
                  'subnet',
                  'port_options',
                  'update_db_option'
                  ]
