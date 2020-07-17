from django.db import models


# Create your models here.

class WanProject(models.Model):
    project_name = models.CharField(max_length=25)
    domain_or_ip = models.CharField(max_length=50)

    def __str__(self):
        return self.domain_or_ip
