from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect
from functools import wraps

def role_required(role):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            print(request.user.role)
            print(role)
            if request.user.is_authenticated and request.user.role == role:
                return view_func(request, *args, **kwargs)
            else:
                return redirect('/login')
        return _wrapped_view
    return decorator
