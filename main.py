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


############### memcaching  ##################

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

def age_str(age):
	s = 'queried %s seconds ago'
	age = int(age)
	if age == 1:
		s = s.replace('seconds', 'second')
	return s % age







########## Possible soultion for adding and viewing a classes within the admin page  ##############

def add_class(ip, post):
	class.put()
	display_classes(update=True)
	return str(class.key().id())


def display_classes(update=False):
	q = db.GqlQuery("SELECT * FROM Class ORDER BY created DESC LIMIT 10")
	mc_key = 'top'
	
	classes, age = age_get(mc_key)
	if classes is None or update:
		classes = list(q)
		age_set(mc_key, classes)
	
	return classes, age



####################################################################################






##### Parent for Google Datastore

#def blog_key(name='default'):
#	return db.Key.from_path('blogs', name)





# Generic helper functions -- including optimized output rendering
# JSON rendering, string creation and cookie setting

class Generic(webapp2.RequestHandler):
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







class MainHandler(Generic):
    def get(self):
    	self.write("Hello World!")
        classes = Class.all().order('-created')
        if self.format == 'html':
            self.render('front.html', class = class)
        else:
            return self.render_json([c.as_dict() for c in classes])










######################## The Class class ##########################



class Class(db.Model):
	"""
	Creates the content entity of the kind "Class". The instance variables below become the entity's properties.
	"""
	subject = db.StringProperty(required=True)	#'require' as parameters upon initialization 		
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	
	def render(self):
		"""
		Each instance has its own rendering format, which governs
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



def render_class(response, post):
	response.out.write('<b />' + class.subject + '<b /><br>')
	response.out.write(class.content)





######################### User Account Signup -- complete with crypto ###########################



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



















######################################### Define url handlers ###################################



# Each tuple handles requests to different paths in the url "dmsc438.appsot.com"
# by mapping its string to one of the above classes.
app = webapp2.WSGIApplication([
    							('/', MainHandler),
    							('/login', Login),
    							('/logout', Logout)
], debug=True)
