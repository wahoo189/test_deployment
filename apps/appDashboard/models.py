from __future__ import unicode_literals

from django.db import models

# Create your models here.
class User(models.Model):
    first_name = models.CharField(max_length=45)
    last_name = models.CharField(max_length=45)
    emailAddress = models. EmailField(max_length=254)
    password = models.CharField(max_length=100)
    description = models.TextField(max_length=255)
    ACCESS_LEVEL_CHOICES = (
        ('NORMAL', 'Normal'),
        ('ADMIN', 'Admin')
    )
    access_level = models.CharField(
        max_length=5,
        choices=ACCESS_LEVEL_CHOICES,
        default='NORMAL',
    )
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

class Message(models.Model):
    message = models.TextField()
    owner = models.ForeignKey(User)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

class Comment(models.Model):
    comment = models.TextField()
    toMessage = models.ForeignKey(Message)
    owner = models.ForeignKey(User)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
