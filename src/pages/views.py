# Controller
from django.shortcuts import render
# forms import
from .forms import RegistrationForm
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate


def index_view(request):
    print(request)
    context = {
    }
    return render(request, "base.html", context)


# CUSTOM REGISTER VIEW
# def register_view(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             password = form.cleaned_data['password']
#             email = form.cleaned_data['email']
#             # With user... we save it to Users provided by django!
#             User.objects.create_user(username, email, password)
#             # form.save() saves into app(pages->Registration)
#             #   form.save()
#             print('User saved in database(Exact location /admin/auth/User)')
#     else:
#         form = RegistrationForm()
#         print('Registration view accessed!')
#     context = {
#         'form': form
#     }
#     return render(request, "userRelated/sign-up.html", context)

def register(response):
    if response.method == "POST":
        form = UserCreationForm(response.POST)
        if form.is_valid():
            form.save()
    else:
        form = UserCreationForm()
    context = {
        'form': form
    }
    return render(response, 'user_authentication/sign-up.html', context)


def help_view(request):
    session_target = request.session.get('target')
    context = {
        'session_var': session_target
    }
    return render(request, 'user_projects/help.html', context)