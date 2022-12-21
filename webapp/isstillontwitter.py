import base64
import re
import json
import logging
import os
import sys
import uuid

import arrow
import flask
from flask import Flask, request, jsonify
from flask_mobility import Mobility
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
# import redis
import jsonschema


ENV_VAR_NAME_REDIS_URL = "REDISCLOUD_URL"
ENV_VAR_NAME_LOGLEVEL = "LOGLEVEL"
ENV_VAR_NAME_TWITTER_TOKEN = "TWITTER_BEARER_TOKEN"

domain_name = "isstillontwitter.fyi"
is_fqdn_regex = re.compile(f"(.*).{domain_name}")
ip_regex = r'((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|' \
           r'25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}' \
           r'|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|' \
           r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|' \
           r'((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|' \
           r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|' \
           r'((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|' \
           r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|' \
           r'((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|' \
           r'1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|' \
           r'1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))'
ip_regex_complied = re.compile(ip_regex)

twitter_scree_name_regex = re.compile(r'^[a-zA-Z0-9_]{1,15}$')

TWITTER_ERROR_MSG_SCHEMA_PATH = "schemas/twitter_error_response_schema.json"

twitter_api_screen_name_lookup_endpoint = "https://api.twitter.com/1.1/users/show.json?screen_name=%(screen_name)s"
twitter_api_timeline_lookup_endpoint = "https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=%(screen_name)s&include_rts=true&count=1"

twitter_api_bearer_token = os.getenv(ENV_VAR_NAME_TWITTER_TOKEN, None)

twitter_api_err_code_user_suspended = 63
twitter_api_err_code_user_notfound = 50

app = Flask(__name__)
app.logger.setLevel(os.getenv(ENV_VAR_NAME_LOGLEVEL, logging.INFO))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

Mobility(app)

try:
    with open(TWITTER_ERROR_MSG_SCHEMA_PATH) as twitter_error_msg_schema_fp:
        app.logger.debug(f"Twitter error file schema file {TWITTER_ERROR_MSG_SCHEMA_PATH}")
        twitter_error_msg_jsonschema = json.load(twitter_error_msg_schema_fp)
except Exception as e:
    app.logger.critical(f"Could not open or access twitter error file schema file "
                        f"'{TWITTER_ERROR_MSG_SCHEMA_PATH}' from '{os.getcwd()}'. err is {e} Can't start. Exiting")
    sys.exit(-1)


class CacheIfCacheCan:
    """
    A wrapper around getting/setting to a redis back end, if configured. A convenience class so code doesn't have to
    repeat boilerplate logic to check if redis has been configured or not. If redis isn't configured getting will
    always return None and setting will just be ignored
    """
    _redis_interface = None

    def __init__(self, redis_interface):
        self._redis_interface = redis_interface

    def get(self, key, is_json=False):
        if self._redis_interface is None:
            return None
        else:
            value = self._redis_interface.get(key)
            if value is None:
                return None
            elif is_json:
                value = json.loads(value)

            return value

    def set(self, key, value, timeout=None, is_json=False):
        if self._redis_interface is None:
            pass
        else:
            if is_json:
                value = json.dumps(value)

            if timeout is None:
                self._redis_interface.set(key, value)
            else:
                self._redis_interface.set(key, value, timeout)


class TwitterAPIException(Exception):
    endpoint = None

    def __init__(self, endpoint, message="Unexpected twitter endpoint behavior"):
        self.endpoint = endpoint
        self.message = message
        super().__init__(self.message)


class TwitterAPIAuthException(TwitterAPIException):
    pass


class TwitterAPIRateLimitedException(TwitterAPIException):
    pass


class TwitterAPIBehaviorException(TwitterAPIException):
    pass


def error_code_is_in_twitter_response(error_response, code):
    jsonschema.validate(error_response, twitter_error_msg_jsonschema)

    error_codes = list(map(lambda err_obj: err_obj['code'], error_response["errors"]))
    in_there = code in error_codes
    return in_there, [x for x in error_codes if x != code]


def serialize_requests_response_to_b64(flask_response: flask.Response):
    response_as_string = f"{flask_response.status_code}\n\n{flask_response.headers}\n\n{str(flask_response)[:1024]}"
    return str(base64.b64encode(response_as_string.encode('ascii')))


def lookup_screen_name_last_activity_time(_):
    """
    timeline_lookup_result = requests.get(
                twitter_api_timeline_lookup_endpoint % {"screen_name": lookup_screen_name},
                headers={"Authorization": f"Bearer {twitter_api_bearer_token}"})

            if timeline_lookup_result.status_code == 200 and len(timeline_lookup_result.json()) >= 1:
                lookup_result["last_active"] = timeline_lookup_result.json()[0]["created_at"]
                lookup_result["lookup_success"] = "full"
                """
    # TODO do activity lookup
    return "Unknown"


def lookup_screen_name(screen_name):

    lookup_result = {
        "name": None,
        "screen_name": screen_name,
        "has_account": False,
        "account_status": "Unknown",
        "last_active": "Unknown",
        "results_timestamp_utc": None
    }

    endpoint = twitter_api_screen_name_lookup_endpoint % {"screen_name": screen_name}

    screen_name_lookup_result = requests.get(endpoint, headers={"Authorization": f"Bearer {twitter_api_bearer_token}"})

    match screen_name_lookup_result.status_code:
        case 200:
            # there is an account
            lookup_result["has_account"] = True
            lookup_result["name"] = screen_name_lookup_result.json()["name"]

            if screen_name_lookup_result.json()["protected"]:
                # the account tweets are locked/protected
                lookup_result["account_status"] = "protected"
                lookup_result["last_active"] = "Unknown"
                lookup_result["lookup_success"] = "full"
            else:
                # the account tweets are public
                lookup_result["account_status"] = "public"
                lookup_result["last_active"] = lookup_screen_name_last_activity_time(screen_name)
        case 404:
            # no account
            is_notfound, extra_codes = error_code_is_in_twitter_response(screen_name_lookup_result.json(), twitter_api_err_code_user_notfound)
            if not is_notfound:
                # Got a 404 but JSON response didn't have the expected err code indicating there is no account by that name
                log_id = str(uuid.uuid4())
                app.logger.info(f"Twitter response to {log_id} {serialize_requests_response_to_b64(screen_name_lookup_result)}")
                raise(TwitterAPIBehaviorException(endpoint, f"Got 404 HTTP but JSON didn't include expected error code {twitter_api_err_code_user_notfound}. logged as {log_id}"))

            # Don't have to do anything if the no found code is in response JSON, default values of lookup_results are fine
        case 403:
            # there is an account but it is suspended
            is_suspended, extra_codes = error_code_is_in_twitter_response(screen_name_lookup_result.json(), twitter_api_err_code_user_suspended)

            if not is_suspended:
                # Got a 403 but JSON response didn't have the expected err code indicating the account exists but is suspended
                log_id = str(uuid.uuid4())
                app.logger.info(f"Twitter response to {log_id} {serialize_requests_response_to_b64(screen_name_lookup_result)}")
                raise(TwitterAPIBehaviorException(endpoint, f"Got 403 HTTP but JSON didn't include expected error code {twitter_api_err_code_user_suspended}. logged as {log_id}"))

            lookup_result["has_account"] = True
            lookup_result["account_status"] = "suspended"
        case 401:
            # API token expired / invalid
            raise TwitterAPIAuthException(endpoint, "API token expired")
        case 429:
            # API rate limited
            raise TwitterAPIRateLimitedException(endpoint, "Rate limit exceeded")
        case _:
            log_id = str(uuid.uuid4())
            app.logger.info(f"Twitter response to {log_id} {serialize_requests_response_to_b64(screen_name_lookup_result)}")
            raise TwitterAPIBehaviorException(endpoint, f"Unhandled status response status code {screen_name_lookup_result.status_code} logged as {log_id}")

    return lookup_result


def do_all_screen_name_lookups(screen_names_list):

    lookup_results = {
        "date": str(arrow.utcnow()),
        "data": {},
        "error_messages": [],
        "warning_messages": []
    }

    for screen_name in screen_names_list:
        try:
            lookup_results['data'][screen_name] = lookup_screen_name(screen_name)

        except TwitterAPIAuthException:
            lookup_results['error_messages'].append(f"Could not look up {screen_name} due to Twitter API authentication issue. Check back later, nothing you can do on your end.")
            continue

        except TwitterAPIRateLimitedException:
            lookup_results['error_messages'].append(f"Could not look up {screen_name} due to Twitter API rate limits. Check back later, nothing you can do on your end.")
            continue

        except TwitterAPIBehaviorException:
            lookup_results['error_messages'].append(f"Could not look up {screen_name} due to Twitter API unexpected behavior. Check back later, nothing you can do on your end.")
            continue

        except TwitterAPIException:
            lookup_results['error_messages'].append(f"Could not look up {screen_name} due to unhandled Twitter API behavior. Check back later, nothing you can do on your end.")
            continue

        except jsonschema.ValidationError as ve:
            app.logger.error("failed to validate twitter response")
            app.logger.error(ve)
            lookup_results["error_messages"].append(f"App error parsing Twitter API response. Check back later")
            continue

        except Exception as ee:
            msg = f"Unhandled exception '{ee}' doing lookup for screen name '{screen_name}'. Not doing other screen names. Check back later, nothing you can do on your end."
            app.logger.error(msg)
            logging.exception(ee)
            lookup_results["error_messages"].append(msg)
            break

    return lookup_results


@app.route('/css/<path:path>')
def send_css(path):
    return flask.send_from_directory('staticfiles/css', path)


@app.route('/js/<path:path>')
def send_js(path):
    return flask.send_from_directory('staticfiles/js', path)


@app.route('/fonts/<path:path>')
def send_font(path):
    return flask.send_from_directory('staticfiles/fonts', path)


@app.route('/media/<path:path>')
def send_media(path):
    return flask.send_from_directory('staticfiles/media', path)


@app.route('/favicon.ico')
def send_icon():
    return [None, 404]


@app.route("/")
@app.route("/index.html")
@app.route("/index.htm")
def default_page():

    screen_name_from_host_name = None

    requested_host = None
    if "X-Forwarded-Host" in request.headers.keys():
        requested_host = request.headers["X-Forwarded-Host"]
    elif "Host" in request.headers.keys():
        requested_host = request.headers["Host"]

    if requested_host is not None:
        # strip off port if there is one
        requested_host = requested_host.split(":")[0]
        requested_host_elements = requested_host.split(".")

        if not re.match(ip_regex_complied, requested_host) and len(requested_host_elements) > 2 and requested_host_elements[0].lower() != "www":
            screen_name_from_host_name = requested_host_elements[0]

    if screen_name_from_host_name is None:
        lookup_results = do_all_screen_name_lookups([])
    else:
        lookup_results = do_all_screen_name_lookups([screen_name_from_host_name])

    if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
        return_json = True
        template = None
    else:
        return_json = False
        # HTML will be returned so figure out if the mobile or desktop template should be used
        if screen_name_from_host_name is None:
            template = "index.jinja2"
        else:
            template = "index_one_screen_name.jinja2"

    if return_json:
        return jsonify(lookup_results), 200
    else:
        return flask.render_template(template,
                                     lookup_results=lookup_results), 200


@app.route("/<lookup_screen_names_list>")
def lookup(lookup_screen_names_list):

    # ignore requests from scanning pests requesting things like xml.php and .env
    if "," not in lookup_screen_names_list and not re.match(twitter_scree_name_regex, lookup_screen_names_list):
        flask.abort(404)

    try:
        # Figure out if the response should be just the JSON data or HTML
        if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
            return_json = True
            template = None
        else:
            return_json = False
            # HTML will be returned so figure out if the mobile or desktop template should be used
            template = "index.jinja2"

        # Split the usernames to lookup
        app.logger.info(f"Look up request for '{lookup_screen_names_list}'")

        lookup_screen_names = lookup_screen_names_list.split(",")

        # make sure more than 5 targets haven't been requested
        if len(lookup_screen_names) > 5:
            # Don't process request, too many targets
            lookup_results = do_all_screen_name_lookups([])
            lookup_results["error_messages"].append(f"Max 5 screen names in request. {len(lookup_screen_names)} provided")
        else:
            lookup_results = do_all_screen_name_lookups(lookup_screen_names)
            print(lookup_results)

    except Exception as ee:
        app.logger.error("Unhandled exception '{}' doing hostname lookup for request '{}'".format(ee, lookup_screen_names_list))
        logging.exception(ee)
        return "Unrecoverable err in doing lookup error is {}".format(ee), 500

    if return_json:
        return jsonify(lookup_results), 200
    else:
        return flask.render_template(template, lookup_results=lookup_results), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
