from django.shortcuts import render, redirect
from .models import User, Message, Comment
import re, datetime, bcrypt
from django.contrib import messages
from django.http import HttpResponseRedirect

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
PASSWORD_CAP_DIG_REGEX = re.compile(r'\d+.*[A-Z]+|[A-Z]+.*\d+')
LOGGED_IN_USER_ID = "LOGGED_IN_USER_ID"

# Create your views here.
def logout(request):
    request.session[LOGGED_IN_USER_ID] = 0
def index(request):
    logout(request)
    return render(request, 'appDashboard/index.html')
def signin(request):
    return render(request, 'appDashboard/signin.html')
def doSignin(request):
    try:
        print "ATTEMPTING TO LOG IN THIS USER: ", request.POST['email']
        user = User.objects.get(emailAddress=request.POST['email'])
        if bcrypt.hashpw(request.POST['password'].encode(), user.password.encode()) == user.password.encode():
            request.session[LOGGED_IN_USER_ID] = user.id

            if user.access_level == 'ADMIN':
                print "REDIRECTING TO ADMIN DASHBOARD"
                return redirect('/dashboard/admin')
            else:
                print "REDIRECTING TO DASHBOARD"
                return redirect('/dashboard')
        else:
            messages.add_message(request, messages.INFO, 'Incorrect Password!')
            return redirect('/signin', request)
    except:
        messages.add_message(request, messages.INFO, 'User not found, please consider registering.')
        return redirect('/register')

def register(request):
    return render(request, 'appDashboard/register.html')
def doRegister(request):
    if tryCreateUser(request):
        return doSignin(request)
    else:
        return redirect('/register')
    # return redirect('/loginRegistration')
    #return redirect('/dashboard')

def admin(request):
    context = { "User" : getLoggedInUser(request), "Users" : User.objects.all() }
    return render(request, 'appDashboard/dashboard.html', context)
def dashboard(request):
    context = { "User" : getLoggedInUser(request), "Users" : User.objects.all() }
    return render(request, 'appDashboard/dashboard.html', context)
def deleteUser(request, id):
    User.objects.get(id=id).delete()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def newUser(request):
    return render(request, 'appDashboard/newUser.html')
def createUser(request):
    tryCreateUser(request)
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def showUser(request, id):
    user = User.objects.get(id=id)
    context = {
        "User" : user,
        "Messages" : Message.objects.filter(owner=user)
    }
    return render(request, 'appDashboard/showUser.html', context)

def editUser(request, id):
    user = User.objects.get(id=id)
    loggedInUser = getLoggedInUser(request)
    context = {
        "User" : user,
        "LoggedInUser" : loggedInUser
    }
    return render(request, 'appDashboard/editUser.html', context)

def updateUserInfo(request):
    loggedInUser = getLoggedInUser(request)

    user = User.objects.get(id=request.POST['id'])
    user.first_name = request.POST['first_name']
    user.last_name = request.POST['last_name']
    user.emailAddress = request.POST['emailAddress']
    if loggedInUser.access_level == 'ADMIN':
        user.access_level = request.POST['access_level']
    user.save()
    messages.add_message(request, messages.INFO, 'Information updated for user ' + user.first_name + " " + user.last_name)
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def updatePassword(request):
    user = User.objects.get(id=request.POST['id'])
    password = request.POST['password']

    if validatePassword(request, password, request.POST['password_confirm']):
        user.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        user.save()
        messages.add_message(request, messages.INFO, 'Password updated.')
    else:
        messages.add_message(request, messages.INFO, 'Invalid password, no changes made.')


    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def updateDescription(request):
    user = User.objects.get(id=request.POST['id'])
    user.description = request.POST['description']
    user.save()
    messages.add_message(request, messages.INFO, 'Description updated for user ' + user.first_name + " " + user.last_name)
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def postMessage(request):
    id = request.POST['id']
    user = User.objects.get(id=id)
    newMessage = Message.objects.create(owner=user, message=request.POST['message'])
    print "NEW MESSAGE IS:",newMessage.message
    #context = { "Messages" : Message.objects.filter(owner=user) }
    print "REFERRING BACK TO ", request.META.get('HTTP_REFERER')
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def postComment(request):
    id = request.POST['userId']
    user = User.objects.get(id=id)
    message = Message.objects.get(id=request.POST['messageId'])
    newComment = Comment.objects.create(owner=user, comment=request.POST['comment'], toMessage=message)
    print "NEW COMMENT IS:", newComment.comment
    #context = { "Messages" : Message.objects.filter(owner=user) }
    print "REFERRING BACK TO ", request.META.get('HTTP_REFERER')
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

# HELPER METHODS
def getLoggedInUser(request):
    if request.session[LOGGED_IN_USER_ID] > 0:
        return User.objects.get(id=request.session[LOGGED_IN_USER_ID])
    else:
        return None

def clearUsers(request):
    User.objects.all().delete()
    return redirect('/')

def validatePassword(request, password, password_confirm):
    errorsExist = False
    # Password should be more than 8 characters
    if len(password) < 8:
        messages.add_message(request, messages.INFO, 'Passwords must contain at least 8 characters!')
        print("Password must contain at least 8 characters!")
        errorsExist = True
    # Password and Password Confirmation should match
    if password != password_confirm :
        messages.add_message(request, messages.INFO, 'Passwords do not match!')
        print("Passwords do not match!")
        errorsExist = True
    # Password to have at least 1 uppercase letter and 1 numeric value.
    if not PASSWORD_CAP_DIG_REGEX.match(password):
        errorsExist = True
        messages.add_message(request, messages.INFO, 'Password must contain at least 1 upper case letter and 1 numeric value')
        print("Password must contain at least 1 upper case letter and 1 numeric value")

    return not errorsExist

# INTERNAL FUNCTIONS
def tryCreateUser(request):
    if registrationValidation(request):
        print "VALIDATION PASSED FOR EMAIL: ", request.POST['email']
        if User.objects.filter(emailAddress=request.POST['email']).count() == 0:
            newUser = {}
            print ("ATTEMPTING TO REGISTER USER")

            bcryptedPW = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())

            if User.objects.all().count() == 0: # Make first user an admin.
                accessLevel = "ADMIN"
            else:
                accessLevel = "NORMAL"

            newUser = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], emailAddress=request.POST['email'], password=bcryptedPW, access_level = accessLevel)

            # print("NEW USER IS:", newUser)
            # context = {"User" : newUser}
            return True

        else:
            print ("USER ALREADY EXISTS: ", request.POST['email'])
            messages.add_message(request, messages.INFO, 'User already exists!')
            return False
    else:
        print ("REGISTRATION FAILED FOR USER: ", request.POST['email'])
        messages.add_message(request, messages.INFO, 'Registration failed for user ' + request.POST['email'])
        return False

def registrationValidation(request):
    errorsExist = False
    try:
        # All fields are required and must not be blank
    	for field in request.POST:
    		#if field.type == "TextField":
            if len(request.POST[field]) < 1:
                print("All fields are required!")
                messages.add_message(request, messages.INFO, 'All fields are required!')
                errorsExist = True
                break

    # First and Last Name cannot contain any numbers
    	if any(char.isdigit() for char in request.POST['first_name'] + request.POST['last_name']):
            messages.add_message(request, messages.INFO, 'Name values cannot contain numbers!')
            print("Name values cannot contain numbers!")
            errorsExist = True

    # Email should be a valid email
    	if len(request.POST['email']) < 1:
            messages.add_message(request, messages.INFO, 'Email cannot be blank!')
            print("Email cannot be blank!")
            errorsExist = True
    	elif not EMAIL_REGEX.match(request.POST['email']):
            messages.add_message(request, messages.INFO, 'Invalid Email Address!')
            print("Invalid Email Address!")
            errorsExist = True

        if not validatePassword(request, request.POST['password'], request.POST['password_confirm']):
            errorsExist = True

    # Validate birthdate
    	# try:
    	# 	DOB = datetime.datetime.strptime(request.POST['DOB'], '%Y-%m-%d')
    	# 	if DOB > datetime.datetime.now():
    	# 		print("Date of birth must be before today")
    	# 		errorsExist = True
        #
    	# except ValueError:
    	# 	print("Incorrect data format, should be YYYY-MM-DD")
    	# 	errorsExist = True

    # No errors?
    	if not errorsExist:
            messages.add_message(request, messages.INFO, "Thanks for submitting your information.")
            print("Thanks for submitting your information.")

    except Exception,e:
        print "ERROR: ", str(e)

    return not errorsExist
    #context = { "Emails" : Email.objects.all(), "Result" : result }
    #return render(request, "appCourses/results.html", context)
