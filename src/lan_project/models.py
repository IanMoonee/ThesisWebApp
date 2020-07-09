from django.db import models


# Database Table ( in database lan_project.usersInput )
class UserProject(models.Model):
    project_name = models.CharField(max_length=25)
    subnet = models.CharField(max_length=30)
    json_data = models.BinaryField()

    # Project's name = Object name
    def __str__(self):
        return self.project_name


class NvdData(models.Model):
    cve = models.CharField(max_length=10000, blank=True)
    status = models.CharField(max_length=10000, blank=True)
    description = models.CharField(max_length=10000, blank=True)
    references = models.CharField(max_length=10000, blank=True)
    phase = models.CharField(max_length=10000, blank=True)
    votes = models.CharField(max_length=10000, blank=True)
    comments = models.CharField(max_length=10000, blank=True)

    def __str__(self):
        return self.cve
