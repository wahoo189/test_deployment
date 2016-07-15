from django.conf.urls import url
from . import views

urlpatterns = [
    # Authorization
    url(r'^$', views.index)
    , url(r'^signin$', views.signin)
    , url(r'^logout$', views.logout)
    , url(r'^doSignin$', views.doSignin)
    # Registration
    , url(r'^register$', views.register)
    , url(r'^doRegister$', views.doRegister)
    # Dashboard
    , url(r'^dashboard/admin$', views.admin)
    , url(r'^dashboard$', views.dashboard)
    # User CRUD
    , url(r'^users/new$', views.newUser)
    , url(r'^users/create$', views.createUser)
    , url(r'^users/show/(?P<id>\d+)$', views.showUser)
    , url(r'^users/edit/(?P<id>\d+)$', views.editUser)
    # EDIT
    , url(r'^updateUserInfo$', views.updateUserInfo)
    , url(r'^updatePassword$', views.updatePassword)
    , url(r'^updateDescription$', views.updateDescription)
    # POST
    , url(r'^postMessage$', views.postMessage)
    , url(r'^postComment$', views.postComment)
    # ADMIN
    , url(r'^clearUsers$', views.clearUsers)
    , url(r'^deleteUser/(?P<id>\d+)$', views.deleteUser)
]
