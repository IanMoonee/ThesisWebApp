from django import forms
# from .models import Registration


# TODO: This is a demonstration of how to save something in the database in a specific app.
#       Change this class cause it redundant.
# class RegistrationForm(forms.ModelForm):
#     class Meta:
#         model = Registration
#         widgets = {
#             'password': forms.PasswordInput(),
#         }
#         fields = [
#             'first_name',
#             'last_name',
#             'username',
#             'password',
#             'email',
#         ]

class RegistrationForm(forms.Form):
    username = forms.CharField(label='Username :', max_length=50, required=True)
    password = forms.CharField(label='Password :', max_length=50, required=True, widget=forms.PasswordInput)
    email = forms.EmailField(label='Email :', max_length=254, required=True)
