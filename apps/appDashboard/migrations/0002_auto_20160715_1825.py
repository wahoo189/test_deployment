# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-07-15 18:25
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('appDashboard', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='comment',
            old_name='user_id',
            new_name='owner',
        ),
        migrations.RenameField(
            model_name='comment',
            old_name='message_id',
            new_name='toMessage',
        ),
    ]