#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os.path
import tornado.auth
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

import redis
import logging
import time
import math

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("facebook_api_key", help="your Facebook application API key",
       default="250748438308110")
define("facebook_secret", help="your Facebook application secret",
       default="7ad8934b8697afdb9f6b6264a12b2332")


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/status", StatusHandler),
            (r"/items/?([0-9]+)?", ItemsHandler),
        ]
        settings = dict(
            cookie_secret="__GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=False,
            facebook_api_key=options.facebook_api_key,
            facebook_secret=options.facebook_secret,
            debug=True,
            autoescape=None,
        )

        self.redis = redis.StrictRedis('127.0.0.1', 6379, db=0)
        self.log = logging

        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("fbdemo_user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)

    def compute_etag(self):
        return None

    @property
    def redis(self):
        return self.application.redis

    @property
    def log(self):
        return self.application.log
    

class StatusHandler(BaseHandler):
    def get(self):
        self.finish({'authed': self.get_current_user() is not None})

class ItemsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, item_id):
        if item_id:      
            data = self.redis.get('bb:post:{0}'.format(item_id))
            if data:
                self.finish(tornado.escape.json_decode(data))
            else:
                raise tornado.web.HTTPError(404)
        else:
            page = int(self.get_argument('page', 1))
            count = int(self.get_argument('count', 10))
            if count > 10:
                count = 10
            if page < 1:
                page = 1

            total = self.redis.zcard("bb:posts")
            if not total:
                total = 0

            total = int(math.ceil(int(total) * 1.0 / count))

            if page <= total:
                items = self.redis.zrevrange("bb:posts", (page - 1) * count, page * count - 1, True)
                keys = map(lambda (item_id, date): "bb:post:{0}".format(item_id), items)
                if keys:
                    data = map(lambda x: tornado.escape.json_decode(x), self.redis.mget(keys))
                else:
                    data = []
            else:
                data = []

            self.finish({'data': data, 'page': page, 'count': count, 'pages': total})

    @tornado.web.authenticated
    def post(self, _):
        body = tornado.escape.json_decode(self.request.body)
        if body.get('type') not in ['text', 'photo', 'video']:
            body['type'] = 'text'

        new_id = self.redis.incr('bb:post:id')
        pipe = self.redis.pipeline()
        result = {
            'id': new_id,
            'date': int(time.time()),
            'author_id': self.get_current_user()['id'],
            'type': body.get('type'),
            'text': body.get('text', '')[:32000]
        }
        pipe.set('bb:post:{0}'.format(new_id), tornado.escape.json_encode(result))
        pipe.zadd('bb:posts', result.get('date'), new_id)
        pipe.execute()

        self.finish(result)

    #@tornado.web.authenticated
    def put(self, item_id):
        body = tornado.escape.json_decode(self.request.body)
        item = self.redis.get('bb:post:{0}'.format(item_id))
        if item:
            data = tornado.escape.json_decode(item)
            if data.get('author_id') != self.get_current_user()['id']:
                raise tornado.web.HTTPError(403)    

            data['text'] = body.get('text', '')[:32000]
            self.redis.set('bb:post:{0}'.format(item_id), tornado.escape.json_encode(data))
            self.finish(data)
        else:
            raise tornado.web.HTTPError(404)

    @tornado.web.authenticated
    def delete(self, item_id):
        item = self.redis.get('bb:post:{0}'.format(item_id))
        if item:
            data = tornado.escape.json_decode(item)
            if data.get('author_id') != self.get_current_user()['id']:
                raise tornado.web.HTTPError(403)    
            self.redis.zrem('bb:posts', item_id)
            self.redis.delete('bb:post:{0}'.format(item_id))
            self.finish({'status': True})
        else:
            raise tornado.web.HTTPError(404)


class MainHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        self.facebook_request("/me", self._on_stream,
                              access_token=self.current_user["access_token"])

    def _on_stream(self, stream):
        if stream is None:
            # Session may have expired
            self.redirect("/auth/login?next=/?backurl={0}".format(tornado.escape.url_escape(self.get_argument('backurl', '/'))))
            return
        
        self.redis.zadd("bb:users", stream.get('id'), stream.get('name'));
        if self.get_argument('backurl', '').startswith('http://'):
            self.redirect(self.get_argument('backurl'))
        else:
            self.finish({'data': stream})


class AuthLoginHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        my_url = (self.request.protocol + "://" + self.request.host +
                  "/auth/login?next=" +
                  tornado.escape.url_escape(self.get_argument("next", "/")))
        if self.get_argument("code", False):
            self.get_authenticated_user(
                redirect_uri=my_url,
                client_id=self.settings["facebook_api_key"],
                client_secret=self.settings["facebook_secret"],
                code=self.get_argument("code"),
                callback=self._on_auth)
            return
        self.authorize_redirect(redirect_uri=my_url,
                                client_id=self.settings["facebook_api_key"],
                                extra_params={"scope": "read_stream"})

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Facebook auth failed")
        self.set_secure_cookie("fbdemo_user", tornado.escape.json_encode(user))
        self.redirect(self.get_argument("next", "/"))


class AuthLogoutHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    def get(self):
        self.clear_cookie("fbdemo_user")
        self.redirect(self.get_argument("next", "/"))

def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()