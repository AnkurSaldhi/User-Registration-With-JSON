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
import webapp2
import jinja2
import re
import os
import hashlib
import hmac
from string import letters
import random
import json

from google.appengine.ext import db


JINJA_ENVIRONMENT = jinja2.Environment(autoescape=True,
loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

secret="mylaptop"

userlist=["hello"]
userlogin=["lan"]
visits=0


def make_salt(length = 5):
        return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
        if not salt:
            salt = make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)



def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
        val = secure_val.split('|')[0]
        if secure_val == make_secure_val(val):
            return val

def login(self,user):
                self.set_secure_cookie(str(user.key().id()))
                



class FunctionHandler(webapp2.RequestHandler):
        def set_secure_cookie(self,val):
                cookie_val = make_secure_val(val)
                self.response.headers.add_header(
                        'Set-Cookie',
                        'name=%s; Path=/'%(cookie_val))

        def read_secure_cookie(self,name):
                cookie_val = self.request.cookies.get(name)
                return cookie_val and check_secure_val(cookie_val)


        
        #def login(self, user):
         #       self.set_secure_cookie(str(user.key().id()))
                

        def logout(self):
                self.response.headers.add_header('Set-Cookie', 'name=; Path=/')



class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()


class MainHandler(FunctionHandler):
    def write_form(self,user="",usererr="",passerr="",verifyerr="",againemail="",emailerr=""):
        template_values = {"useragain":user,
                           "usererror":usererr,
                           "passerror":passerr,
                           "verifyerror":verifyerr,
                           "againemail":againemail,
                           "emailerror":emailerr}

        template = JINJA_ENVIRONMENT.get_template('form.html')
        self.response.out.write(template.render(template_values))

    
    def get(self):
        self.write_form()

    def post(self):

        usererr=""
        passerr=""
        verifyerr=""
        emailerr=""
        have_error=""
        email=""
        
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        
        def valid_username(username):
            if USER_RE.match(username):
                return "valid"
            else:
                return


        def valid_password(password):
            if PASSWORD_RE.match(password):
                return "valid"
            else:
                return


        def valid_email(email):
            if EMAIL_RE.match(email):
                return "valid"
            else:
                return


        username=self.request.get('username')
        userlist.pop(0)
        userlist.append(username)
        password=self.request.get('password')
        verify=self.request.get('verify')
        email=self.request.get('email')
        
        user_chk=valid_username(username)
        pass_chk=valid_password(password)
        email_chk=valid_email(email)

        #self.response.out.write(pass_chk)
        
        if not user_chk:
            #self.write_form("","please enter valid username","","","")
            usererr="enter a valid username"
            have_error=True

        if not pass_chk:
            passerr="enter a valid password"
            have_error=True
        elif password!=verify:
            verifyerr="your passwords didn't match"
            have_error=True

        if email:
            if not email_chk:
                emailerr="enter a valid email"
                have_error=True

        if have_error==True:
            self.write_form(username,usererr,passerr,verifyerr,email,emailerr)
        else:
            #username=self.request.get('username')
            #self.response.out.write(self.username)
            #self.response.out.write("hello")
            u = User.all().filter('name =',username).get()
            if u:
                usererr="user already exists"
                self.write_form(username,usererr,"","",email,"")
            else:
                pw_hash=make_pw_hash(username,password)
                u=User(name=username,pw_hash=pw_hash,email=email)
                u.put()
                login(self,u)
                self.redirect('/signup/welcome')


class WelcomeHandler(FunctionHandler):
    def get(self):
        #username=self.request.get('username')
        usr=userlist[0]
        value=self.read_secure_cookie('name')
        if value: 
                self.response.out.write("welcome!"+ usr)
        else:
                self.redirect('/signup')

                
        #self.response.out.write(usr)
        #self.response.headers['Content-Type']='text/plain'
        #visits=0
        #visit_cookie_str=""
        #visit_cookie_str = self.request.cookies.get('name')
        #self.response.out.write(visit_cookie_str)
       # if visit_cookie_str:
        #    cookie_val=check_secure_val(visit_cookie_str)
         #   if cookie_val:
          #      visits=int(cookie_val)

        #visits+=1

        #new_cookie_val=make_secure_val(str(visits))
        #self.response.out.write(new_cookie_val)   
        #visits=self.request.cookies.get('visits','0')
        # make sure visits is an int
        #if visits.isdigit():
         #   visits=int(visits)+1
        #else:
         #   visits=0
        #self.response.headers.add_header('Set-Cookie','name=%s'%new_cookie_val




class LoginHandler(FunctionHandler):
        def write(self,invaliderror=""):
                template_values={"invaliderror":invaliderror}

                template = JINJA_ENVIRONMENT.get_template('login.html')
                self.response.out.write(template.render(template_values))


        def get(self):
                self.write()


        def post(self):
                username=self.request.get('username')
                userlogin.pop(0)
                userlogin.append(username)
                password=self.request.get('password')

                u=User.all().filter('name =',username).get()
                if u and valid_pw(username,password,u.pw_hash):
                        login(self,u)
                        self.redirect('/login/welcome')
                else:
                        invaliderror="Invalid Login"
                        self.write(invaliderror)


class WelcomeLogin(FunctionHandler):
        def get(self):
                username=userlogin[0]
                value=self.read_secure_cookie('name')
                if value: 
                        self.response.out.write("welcome!"+ username)
                else:
                        self.redirect('/login')


class LogoutHandler(FunctionHandler):
        def get(self):
                self.logout()
                self.redirect('/signup')
                





# blog content



class Blog(db.Model):
    subject=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    last_mod = db.DateTimeProperty(auto_now=True)
    #id=db.StringProperty(required=True)

    #self.content.replace('\n', '<br>')


class MainBlogHandler(webapp2.RequestHandler):
    def get(self):
        self.redirect("/blog")
        

class BlogHandler(webapp2.RequestHandler):
    def get(self):
        #self.response.out.write("hello")
        blogs=db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 10")
        #results=arts.fetch(10)
        #for result in results:
            #result.delete()
        #db.delete(results)
        template_values = {
                           'blogs':blogs
                          }
        
        #self.render("form.html", title=title, art=art, error=error,arts=arts)
        template = JINJA_ENVIRONMENT.get_template('blogsfrontpage.html')
        self.response.out.write(template.render(template_values))


class SubmitHandler(webapp2.RequestHandler):
    def write(self,subject="",content="",error=""):
        #blogs=db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 5")
        #results=blogs.fetch(10)
        #for result in results:
            #result.delete()
        #db.delete(results)
        template_values = {'subject':subject,
                           'content':content,
                           'error': error,
                          }
        
        #self.render("form.html", title=title, art=art, error=error,arts=arts)
        template = JINJA_ENVIRONMENT.get_template('blogform.html')
        self.response.out.write(template.render(template_values))
    
        
    def get(self):
        self.write()


    def post(self):
        subject=self.request.get("subject")
        content=self.request.get("content")
        blogs=db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 5")
        if subject and content:
            a=Blog(subject=subject,content=content)
            a.put()
            #results=blogs.fetch(50)
            #for result in results:
                #result.delete()
                #db.delete(results)
            self.redirect('/blog/%s' % str(a.key().id()))

        else:
            error="enter both subject and content"
            self.write(subject,content,error)


class PermalinkHandler(webapp2.RequestHandler):
    def get(self,blog_id):

        #self.response.out.write("data entered in database successfully")
        #self.response.out.write(a.subject,a.content)
        blog_entry=Blog.get_by_id(int(blog_id))
        #self.response.out.write(blog_entry.subject)
        #blog_entry.content.replace('\n','<br>')
        #self.response.out.write(blog_entry.content)
        #topblog=db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 1")
        #subm=db.GqlQuery("SELECT * FROM Blog where id = %s" %blog_id)
        template_values={'topblog':blog_entry}
                        
        template = JINJA_ENVIRONMENT.get_template('permalinkpost.html')
        self.response.out.write(template.render(template_values))






class BlogJsonHandler(webapp2.RequestHandler):
    def get(self):
        blogs = db.GqlQuery("select * from Blog order by created DESC limit 10")
        timeformat = '%a %b %d %H:%M:%S %Y'
        pythondict = [{'subject':p.subject,
                       'content':p.content,
                       'created':p.created.strftime(timeformat),
                       'last_mod':p.last_mod.strftime(timeformat)}
                      for p in blogs]
                      
        jsonString = json.dumps(pythondict)
        self.response.out.write(pythondict)
        self.response.out.write('<br>','<br>')
        #self.response.out.write(pythondict)
        #self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.headers["Content-Type"] = "application/json; charset=UTF-8" 
        self.response.out.write(jsonString)





class JsonPermalinkHandler(webapp2.RequestHandler):
        
        def get(self,blog_id):
                blog=Blog.get_by_id(int(blog_id))   #Query to lookup the Post with id=post_id 
                if not blog:
                    self.error(404)
                    return

                timeformat = '%a %b %d %H:%M:%S %Y'
                
                pythondict = [{'subject':blog.subject,
                                'content':blog.content,
                                'created':blog.created.strftime(timeformat),
                                'last_mod':blog.last_mod.strftime(timeformat)} ]
        
                jsonString = json.dumps(pythondict)    #this converts pythondict to JSON
                self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'

                self.response.out.write(jsonString)







                                  
    
app = webapp2.WSGIApplication([
     ('/signup', MainHandler),('/signup/welcome',WelcomeHandler),('/login',LoginHandler),('/login/welcome',WelcomeLogin),
     ('/logout',LogoutHandler),('/', MainBlogHandler),('/blog', BlogHandler),
     ('/.json',BlogJsonHandler),('/newpost', SubmitHandler),
     ('/blog/([0-9]+)', PermalinkHandler), ('/blog/([0-9]+).json', JsonPermalinkHandler)
     ], debug=True)
