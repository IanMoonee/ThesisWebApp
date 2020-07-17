from django.shortcuts import render


def index_view(request):
    print(request)
    context = {
    }
    return render(request, "base.html", context)


def help_view(request):
    session_target = request.session.get('target')
    context = {
        'session_var': session_target
    }
    return render(request, 'user_projects/help.html', context)