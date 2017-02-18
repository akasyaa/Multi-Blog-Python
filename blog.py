import os
import re
import webapp2
import jinja2
import hashlib
import hmac
import random

from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# REGEX VALIDATING FUNCTIONS (Currently not in use)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# GLOBAL SECURITY FUNCTIONS #########

secret = '.#@Kdn#2spbn*&dkEFN343&%$!'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=10):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return '%s|%s' % (salt, h)


def check_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)

# DATABASE MODELS #########


class User(db.Model):
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=None)

    @classmethod
    def by_name(cls, name):
        return cls.all().filter('name =', name).get()

    @classmethod
    def create(cls, name, password, email=None):
        pw_hash = make_pw_hash(name, password)
        return cls(name=name, password=pw_hash, email=email)

    @classmethod
    def login(cls, name, password):
        user = cls.by_name(name)
        if user and check_pw(name, password, user.password):
            return user


class Post(db.Model):
    userid = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)
    liked = db.IntegerProperty(default=0)

    def render(self, user=None):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('blog_post.html', p=self, user=user)


# This database model keeps track of the
# list of users who liked a particular post
class LikedUser(db.Model):
    userid = db.IntegerProperty(required=True)
    postid = db.IntegerProperty(required=True)


class Comment(db.Model):
    userid = db.IntegerProperty(required=True)
    postid = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self, user=None):
        return render_str('comment.html', c=self, user=user)


# GENERAL HANDLERS #########


# This handler handles basic template functions as well as cookie handling,
# login, and logout.


class Handler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


# This handler renders a main page.


class MainPage(Handler):
    def get(self):
        self.render('main.html', user=self.user)


# This handler renders a signup page with appropriate validation.


class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        self.name = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        if self.name and self.password and self.verify:
            if not self.password == self.verify:
                pwderror = 'Your passwords did not match.'
                self.render_signup(self.name, self.email, '', pwderror)
            else:
                self.register()
        else:
            error = 'Please fill out the form.'
            self.render_signup(self.name, self.email, error)

    def render_signup(self, name='', email='', error='', pwderror=''):
        self.render('signup.html', name=name, email=email,
                    error=error, pwderror=pwderror)

    def register(self):
        user = User.by_name(self.name)

        if user:
            error = 'User already exists. Please choose different username.'
            self.render_signup(self.name, self.email, error)
        else:
            user = User.create(self.name, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/welcome')


# This handler renders a welcome page, accessible after signup or login.


class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', name=self.user.name, user=self.user)
        else:
            self.redirect('/signup')


# This handler renders a login page.


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        self.name = self.request.get('username')
        self.password = self.request.get('password')

        user = User.login(self.name, self.password)

        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            error = 'Invalid login information.'
            self.render('login.html', error=error)


# This handler handles a logout function


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

# BLOG HANDLERS #########

# This handler renders a main page for blog.
# It automatically redirects user if not signed up
# (also applicable for ALL handlers below)


class BlogMain(Handler):
    def get(self):
        if not self.user:
            self.redirect('/login')
            return

        posts = Post.all().order('-created')

        notice = ''
        if Post.all().count() == 0:
            notice = 'No posts yet!'

        self.render('blog_main.html', posts=posts,
                    notice=notice, user=self.user)


# This handler renders a permalink page for a specific blog post


class BlogPost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return

        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        if not post:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return

        comments = Comment.all().filter('postid =',
                                        int(post_id)).order('-created')

        self.render('blog_perma.html', post=post,
                    user=self.user, comments=comments)


# This hanlder renders a new blog post form with appropriate validation


class NewPost(Handler):
    def get(self):
        if not self.user:
            self.redirect('/login')
            return

        self.render('new_post.html', user=self.user)

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(userid=self.user.key().id(),
                        subject=subject, content=content)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = 'Please fill in the form.'
            self.render('new_post.html', user=self.user, subject=subject,
                        content=content, error=error)


# This hanlder renders a edit post form.


class EditPost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return

        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        if not post:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return
        elif not post.userid == self.user.key().id():
            error = 'Error 401. You are unauthorized to view this page.'
            self.render('error.html', error=error, user=self.user)
            return

        self.render('edit_post.html', user=self.user, post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject == '' or content == '':
            error = 'Please fill in the form.'
            self.render('edit_post.html', user=self.user,
                        post=post, error=error)
            return

        post.subject = self.request.get('subject')
        post.content = self.request.get('content')

        post.put()
        self.redirect('/blog/%s' % str(post.key().id()))

# This handler handles a blog post deletion.


class DeletePost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return

        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        if not post:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return
        elif not post.userid == self.user.key().id():
            error = 'Error 401. You are unauthorized to view this page.'
            self.render('error.html', error=error, user=self.user)
            return

        post.delete()
        self.render('delete_success.html')


# This handler handles a blog post like function.
# It checks to see if user already liked a particular post.


class LikePost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return

        userid = self.user.key().id()
        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        if not post:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return
        elif post.userid == userid:
            error = 'Error 401. You are unauthorized to view this page.'
            self.render('error.html', error=error, user=self.user)
            return

        # Check if this user has already liked this particular post
        q = LikedUser.all().filter('userid =', userid).ancestor(post)

        if q.get():
            error = 'You already liked this post.'
            self.render('error.html', error=error, user=self.user)
            return
        else:
            liked_user = LikedUser(userid=userid,
                                   postid=post.key().id(),
                                   parent=post)

        post.liked = post.liked + 1
        post.put()
        liked_user.put()
        self.redirect('/blog/%s' % post_id)


# This handler handles the creation of new comment.


class NewComment(Handler):
    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
            return

        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        if not post:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return

        content = self.request.get('comment')

        if not content:
            self.redirect('/blog/%s' % post_id)
        else:
            comment = Comment(userid=self.user.key().id(),
                              postid=int(post_id),
                              username=self.user.name, content=content)
            comment.put()
            self.render('create_success_c.html', postid=post_id)


# This handler is responsible for deleting a comment.


class DeleteComment(Handler):
    def get(self, comment_id):
        if not self.user:
            self.redirect('/login')
            return

        comment = Comment.get_by_id(int(comment_id))

        if not comment:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return
        elif not comment.userid == self.user.key().id():
            error = 'Error 401. You are unauthorized to view this page.'
            self.render('error.html', error=error, user=self.user)
            return

        comment.delete()
        self.render('delete_success_c.html', postid=comment.postid)


# This handler is responsible for editing a comment.


class EditComment(Handler):
    def get(self, comment_id):
        if not self.user:
            self.redirect('/login')
            return

        comment = Comment.get_by_id(int(comment_id))

        if not comment:
            error = 'Error 404. Page does not exist.'
            self.render('error.html', error=error, user=self.user)
            return
        elif not comment.userid == self.user.key().id():
            error = 'Error 401. You are unauthorized to view this page.'
            self.render('error.html', error=error, user=self.user)
            return

        self.render('edit_comment.html', user=self.user, comment=comment)

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))

        if self.request.get('comment') == '':
            msg = 'Comment cannot be empty.'
            self.render('edit_status_c.html',
                        msg=msg, postid=comment.postid)
            return

        comment.content = self.request.get('comment')

        comment.put()
        msg = 'Comment successfully edited.'
        self.render('edit_status_c.html', msg=msg, postid=comment.postid)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog/?', BlogMain),
    ('/blog/([0-9]+)', BlogPost),
    ('/blog/([0-9]+)/edit', EditPost),
    ('/blog/([0-9]+)/delete', DeletePost),
    ('/blog/([0-9]+)/like', LikePost),
    ('/blog/([0-9]+)/ca', NewComment),
    ('/blog/([0-9]+)/ce', EditComment),
    ('/blog/([0-9]+)/cd', DeleteComment),
    ('/blog/new', NewPost),
    ('/welcome', Welcome)
], debug=True)
