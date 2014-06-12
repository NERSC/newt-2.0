from django.contrib import auth

def is_logged_in(request):
    if (request.user is not None) and (request.user.is_authenticated()):
        output=dict(auth=True,
                    username=request.user.username,
                    session_lifetime=request.session.get_expiry_age(),
                    newt_sessionid=request.session.session_key)
    else:
        output=dict(auth=False,
                    username=None,
                    session_lifetime=0,
                    newt_sessionid=None)
    return output


def get_status(request):
    return is_logged_in(request)


def login(request):

    username = request.POST['username']
    password = request.POST['password']
    user = auth.authenticate(username=username, password=password)
    if user is not None:
        auth.login(request, user)

    return is_logged_in(request)

def logout(request):
    auth.logout(request)

    return is_logged_in(request)