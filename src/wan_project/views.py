from django.shortcuts import render, redirect
from django.views import View
from .forms import WanModelForm


class WanProject(View):
    form_class = WanModelForm
    template_name = 'user_projects/WAN/WANSettings.html'

    def get(self, request):
        form = self.form_class
        context = {
            'form': form
        }
        print('WanProject GET method accessed.')
        return render(request, self.template_name, context)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            print('POST method accessed')
            target = form.cleaned_data['domain_or_ip']
            project_name = form.cleaned_data['project_name']
            request.session['domain_or_ip'] = target
            print('Form is valid, redirecting....')
            return redirect('/WanDashboard')
        return render(request, self.template_name, context={'form': form})


def redir_wan_dashboard(request):
    print('Redirecting to WanProject\'s dashboard')
    context = {
    }
    return render(request, 'user_projects/WAN/WanDashboard.html', context)
