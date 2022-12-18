import re
import json
import logging
import os
import urllib.parse
import sys
import datetime

import arrow
import flask
from flask import Flask, request, jsonify
from flask_mobility import Mobility
import requests
import redis
import jsonschema

ENV_VAR_NAME_REDIS_URL = "REDISCLOUD_URL"
ENV_VAR_NAME_LOGLEVEL = "LOGLEVEL"
ENV_VAR_NAME_TWITTER_TOKEN = "TWITTER_BEARER_TOKEN"

TWITTER_ERROR_MSG_SCHEMA_PATH = "schemas/twitter_error_response_schema.json"

twitter_api_screen_name_lookup_endpoint = "https://api.twitter.com/1.1/users/show.json?screen_name=%(screen_name)s"
twitter_api_timeline_lookup_endpoint = "https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=%(screen_name)s&include_rts=true&count=1"

twitter_api_bearer_token = os.getenv(ENV_VAR_NAME_TWITTER_TOKEN, None)

twitter_api_err_code_user_suspended = 63
twitter_api_err_code_user_notfound = 50

app = Flask(__name__)
app.logger.setLevel(os.getenv(ENV_VAR_NAME_LOGLEVEL, logging.INFO))
Mobility(app)

try:
    with open(TWITTER_ERROR_MSG_SCHEMA_PATH) as twitter_errormsg_schema_fp:
        app.logger.debug(f"Twitter error file schema file {TWITTER_ERROR_MSG_SCHEMA_PATH}")
        twitter_error_msg_jsonschema = json.load(twitter_errormsg_schema_fp)
except Exception as e:
    app.logger.critical(f"Could not open or access twitter error file schema file "
                        f"'{TWITTER_ERROR_MSG_SCHEMA_PATH}' from '{os.getcwd()}'. Can't start. Exiting")
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


def error_code_is_in_twtitter_response(error_response, code):
    jsonschema.validate(error_response, twitter_error_msg_jsonschema)

    error_codes = list(map(lambda errobj: errobj['code'], error_response["errors"]))
    in_there = code in error_codes
    return in_there, [x for x in error_codes if x != code]


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
    return flask.render_template("index.jinja2")


@app.route("/<lookup_screen_names_list>")
def lookup(lookup_screen_names_list):
    app.logger.info(f"Look up request for '{lookup_screen_names_list}'")

    lookup_results = {
        "date": str(arrow.utcnow()),
        "data": {},
        "error_messages": [],
        "warning_messages": []
    }

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
        lookup_screen_names = lookup_screen_names_list.split(",")

        # make sure more than 5 targets haven't been requested
        if len(lookup_screen_names) > 5:
            # Don't process request, too many targets
            lookup_results["error_messages"].append(f"Max 5 targets in request. {len(lookup_screen_names)} provided")

    except Exception as e:
        return "Unrecoverable err in processing request error is {}".format(e), 500

    try:
        for lookup_screen_name in lookup_screen_names:
            lookup_results["data"][lookup_screen_name] = {
                "name": None,
                "screen_name": lookup_screen_name,
                "has_account": False,
                "account_status": "Unknown",
                "last_active": "Unknown",
                "lookup_success": "Unknown"
            }

            screen_name_lookup_result = requests.get(twitter_api_screen_name_lookup_endpoint % {"screen_name": lookup_screen_name},
                                                     headers={"Authorization": f"Bearer {twitter_api_bearer_token}"})

            if screen_name_lookup_result.status_code == 200:
                lookup_results["data"][lookup_screen_name]["has_account"] = True
                lookup_results["data"][lookup_screen_name]["name"] = screen_name_lookup_result.json()["name"]

                if screen_name_lookup_result.json()["protected"]:
                    lookup_results["data"][lookup_screen_name]["account_status"] = "protected"
                    lookup_results["data"][lookup_screen_name]["last_active"] = "Unknown"
                    lookup_results["data"][lookup_screen_name]["lookup_success"] = "full"

                else:
                    lookup_results["data"][lookup_screen_name]["account_status"] = "public"

                    timeline_lookup_result = requests.get(
                        twitter_api_timeline_lookup_endpoint %  {"screen_name": lookup_screen_name},
                        headers={"Authorization": f"Bearer {twitter_api_bearer_token}"})

                    if timeline_lookup_result.status_code == 200 and len(timeline_lookup_result.json()) >= 1:
                        print(timeline_lookup_result.json())
                        lookup_results["data"][lookup_screen_name]["last_active"] = timeline_lookup_result.json()[0][
                            "created_at"]
                        lookup_results["data"][lookup_screen_name]["lookup_success"] = "full"
                    else:
                        app.logger.info(
                            f"timeline request for {lookup_screen_name} returned unexpected result, moving on. status code {timeline_lookup_result.status_code}, len {len(timeline_lookup_result.json())}")
                        lookup_results["data"][lookup_screen_name]["last_active"] = "Unknown"
                        lookup_results["data"][lookup_screen_name]["lookup_success"] = "partial - timeline"


            elif screen_name_lookup_result.status_code == 401:
                # Token is bad?
                app.logger.error(
                    f"Twttier API token may be expired. Request to screen name lookup endpoint for {lookup_screen_name} returned {screen_name_lookup_result.status_code} instead of 200. Bailing")
                lookup_results["error_messages"].append(
                    f"App error making Twitter API request because of an authentication issue. Check back later")
                lookup_results["data"][lookup_screen_name]["lookup_success"] = "failure - apiauth"
                break

            elif screen_name_lookup_result.status_code == 404:
                is_notfound, extra_codes = error_code_is_in_twtitter_response(screen_name_lookup_result.json(),
                                                                              twitter_api_err_code_user_notfound)
                if is_notfound:
                    lookup_results["data"][lookup_screen_name]["has_account"] = False
                    if len(extra_codes) > 1:
                        app.logger.info(
                            f"Got extra codes from twitter api for not found screen name {lookup_screen_name}. codes {str(extra_codes)}")
                        lookup_results["data"][lookup_screen_name]["lookup_success"] = "partial - extra codes"
                    else:
                        lookup_results["data"][lookup_screen_name]["lookup_success"] = "full"
                    continue
                else:
                    app.logger.info(
                        f"twitter api returned 404 for screen name {lookup_screen_name} but not correct error code {twitter_api_err_code_user_notfound}")
                    lookup_results["data"][lookup_screen_name]["lookup_success"] = "no - 404 but wrong err code"

            elif screen_name_lookup_result.status_code == 403:
                # 403 gets returned if account is suspended

                is_suspended, extra_codes = error_code_is_in_twtitter_response(screen_name_lookup_result.json(),
                                                                               twitter_api_err_code_user_suspended)
                if is_suspended:
                    lookup_results["data"][lookup_screen_name]["has_account"] = True
                    lookup_results["data"][lookup_screen_name]["account_status"] = "suspended"
                    lookup_results["data"][lookup_screen_name]["last_active"] = "Unknown"
                    if len(extra_codes) > 1:
                        app.logger.info(
                            f"Got extra codes from twitter api for suspended screen name {lookup_screen_name}. codes {str(extra_codes)}")
                        lookup_results["data"][lookup_screen_name]["lookup_success"] = "partial - extra codes"
                    else:
                        lookup_results["data"][lookup_screen_name]["lookup_success"] = "full"
                    continue
                else:
                    app.logger.info(
                        f"twitter api returned 404 for screen name {lookup_screen_name} but not correct error code {twitter_api_err_code_user_suspended}")
                    lookup_results["data"][lookup_screen_name]["lookup_success"] = "no - 403 but wrong err code"

            else:
                app.logger.error(f"API call to look up screen name {lookup_screen_name} returned unexpected status code {timeline_lookup_result.status_code}. Bailing")
                lookup_results["error_messages"].append(f"App error parsing Twitter API response. Check back later")
                break

    except jsonschema.ValidationError as ve:
        app.logger.error("failed to validate twitter response")
        app.logger.error(ve)
        lookup_results["error_messages"].append(f"App error parsing Twitter API response. Check back later")

    except Exception as ee:
        app.logger.error(
            "Unhandled exception '{}' doing hostname lookup for request '{}'".format(ee, lookup_screen_names))
        logging.exception(ee)
        return "Unrecoverable err in doing lookup error is {}".format(ee), 500

    if return_json:
        return jsonify(lookup_results), 200
    else:
        return flask.render_template(template,
                                     lookup_results=lookup_results), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
