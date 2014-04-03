#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
from string import letters
import json

import random
import string
import hashlib
import hmac
import logging
import time
from datetime import datetime

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache

#assign our template directory to a variable
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

#create jinja2 Environment constructor that we can then process our templates through
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)


#Ideally, SECRET would be in another module that we import
SECRET = 'google'

def render_str(template, **params):
		t = jinja_env.get_template(template)	#Get the template. Our jinja2 variable is configured to search the template directory
		return t.render(params)


def make_secure_val(s):
	return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())

def check_secure_val(s):
	val = s.split('|')[0]
	if s == make_secure_val(val):
		return val
	else:
		return None


############### memcaching ##################

def age_set(key, value):
	save_time = datetime.utcnow()
	memcache.set(key, (value, save_time))

def age_get(key):
	r = memcache.get(key)
	if r:
		val, save_time = r
		age = (datetime.utcnow() - save_time).total_seconds()
	else:
		val, age = None, 0
	return val, age

def add_post(ip, post):
	post.put()
	display_posts(update=True)
	return str(post.key().id())


def display_posts(update=False):
	q = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
	mc_key = 'top'
	
	posts, age = age_get(mc_key)
	if posts is None or update:
		posts = list(q)
		age_set(mc_key, posts)
	
	return posts, age

def age_str(age):
	s = 'queried %s seconds ago'
	age = int(age)
	if age == 1:
		s = s.replace('seconds', 'second')
	return s % age

###################################################



### Blog Stuff ######

class Handler(webapp2.RequestHandler):
	"""
	Helper response handler class for extracting template forms 
	"""
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_json(self, d):
		json_txt = json.dumps(d)
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		self.write(json_txt)
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('valid', str(user.key().id()))

	#logs out user by deleting the cookie
	def logout(self):
		self.response.headers.add_header(
			'Set-Cookie', 
			'token=deleted;',
			'path=/;',
			'expires=Thu, 01 Jan 1970 00:00:00 GMT')


	#App Engine framework can check to see if a user is logged in when a page loads
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('valid')
		self.user = uid and User.by_id(int(uid))

		if self.request.url.endswith('.json'):
			self.format = 'json'
		else:
			self.format = 'html'


class BlogFront(Handler):
    def get(self):
        posts = Post.all().order('-created')
        if self.format == 'html':
            self.render('front.html', posts = posts)
            
        else:
            return self.render_json([p.as_dict() for p in posts])



def render_post(response, post):
	response.out.write('<b />' + post.subject + '<b /><br>')
	response.out.write(post.content)



#Parent for Google Datastore
def blog_key(name='default'):
	return db.Key.from_path('blogs', name)


class Post(db.Model):
	"""
	Creates the content entity of the kind "Post". The instance variables below become the entity's properties.
	"""
	subject = db.StringProperty(required=True)	#'require' as parameters upon initialization 		
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	
	def render(self):
		"""
		Each post has its own rendering format, which governs
		display when .render() is called on any page.
		"""
		self._render_text = self.content.replace('\n', '<br />')	
		return render_str("post.html", p=self)

	# we create a dictionary representation of the object so it can be passed as JSON
	def as_dict(self):
		time_fmt = '%c'
		d = {'subject': self.subject,
			 'content': self.content,
			 'created': self.created.strftime(time_fmt),
			 'last_modified': self.last_modified.strftime(time_fmt)}
		return d




class PostPage(Handler):
	"""
	This class will be used to handle requests to the each post's unique permalink page
	"""
	def get(self, post_id):
		"""
		Makes a key to lookup the post using the 'from_path' function,
		which finds the "Post" with the int(post_id).
		'post_id' is passed in as a parameter by the URL when the handler is called
		If we can't find it, return a 404;
		If we can, render the appropriate permalink page. 
		"""
		post_key = 'POST_' + post_id	

		post, age = age_get(post_key)	#attempt to retrieve from cache
		if not post:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)	#attempts to extract post from the database
			age_set(post_key, post)		#set post to the cache
			age = 0

		if not post:
			self.error(404)
			return
		
		#If we find it, render the permalink.html page, infused with the post content
		if self.format == 'html':
			self.render('permalink.html', post=post, age=age_str(age))
		else:
			self.render_json(post.as_dict())



class NewPost(Handler):
	"""
	Handles our environment for creating new posts
	"""
	def get(self):
		if self.user:	
			self.render("newpost.html")
		else:
			self.redirect('/login')

	def post(self):
		if not self.user:
			self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')

		
		#Create a Post entity for our App Engine database
		if subject and content:
			p = Post(parent=blog_key(), subject=subject, content=content)
			#save the new content to the db and redirect to its unique url
			p.put()
			top_posts(True)
			display_last_caching(True)
			self.redirect('/blog/%s' % str(p.key().id()))  #When a post is stored, AppEngine auto generates a key for it. 


		if subject and not content:
			error = "We cant post \"" + subject + "\" without any content!"
			self.render('newpost.html', subject=subject, error=error)

		if content and not subject:
			error = "Thanks for the content -- but we can't post it without a subject!"
			self.render('newpost.html', content=content, error=error)

		else:
			error = "You didn't give us anything to post!"
			self.render('newpost.html', subject=subject, content=content, error=error)



############################################################## User Account Signup #####################################################################



def make_salt(length=5):
	"""
	returns a string of 5 random
	letters using python's random module.
	"""
	return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt = None):		#passing in salt as a default makes the function flexlble for creation and verification
    if not salt:
    	salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, h)


def valid_pw(name, pw, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, pw, salt)

#creates ancestor element in the database to store all of our users
def users_key(group = 'default'):
	return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u




USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)


class Signup(Handler):
	"""
	Helper class that's inherited by Register
	"""
	def get(self):
		self.render('signup-form.html')

	
	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username=self.username,
					  email=self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render("signup-form.html", **params)
		else:
			
			self.done()



	def done(self, *a, **kw):
		raise NotImplementedError



class Register(Signup):
	"""
	Inherits from Signup to handle the registration process
	"""
	def done(self):
		#make sure the user doesn't already exists
		u = User.by_name(self.username)
		if u:
			msg = "That user already exists."
			self.render('signup-form.html', error_username=msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()		#Now we store the user. 

			self.login(u)	#set the cookie / refers back up to the main handler's login function
			
			self.redirect('/welcome')








class Login(Handler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username, password)
		if u:
			self.login(u)	#handler method to set cookie
			self.redirect('/welcome')
		else:
			msg = "Invalid login"
			self.render('login-form.html', error=msg)

	### add option (link or button) to sign up


class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/login')



class WelcomeUser(Handler):
	def get(self):
		if self.user:
			self.render('welcome.html', username=self.user.name)
			return
		else:
			self.redirect('/signup')
		



app = webapp2.WSGIApplication([
    ('/', BlogFront),
    ('/blog', BlogFront),
    ('/blog/newpost', NewPost),
    ('/blog/?(?:\.json)?', BlogFront),
    ('/blog/([0-9]+)(?:\.json)?', PostPage),	#anything in () will be passed as a parameter into PostPage's get or post handler
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
	('/welcome', WelcomeUser)
], debug=True)
