# This is the VCL file for Varnish, adjusted for Miraheze's needs.
# It was originally written by Southparkfan in 2015, but rewritten in 2022 by John.
# Some material used is inspired by the Wikimedia Foundation's configuration files.
# Their material and license is available at https://github.com/wikimedia/puppet

# Marker to tell the VCL compiler that this VCL has been adapted to the
# new 4.1 format.
vcl 4.1;

# Import some modules used
import directors;
import std;
import vsthrottle;

# MediaWiki configuration
probe mwhealth {
	.request = "GET /wiki/Main_Page HTTP/1.1"
		"Host: login.miraheze.org"
		"User-Agent: Varnish healthcheck"
		"Connection: close";
	# Check each <%= @interval_check %>
	.interval = <%= @interval_check %>;
	# <%= @interval_timeout %> should be our upper limit for responding to a fair light web request
	.timeout = <%= @interval_timeout %>;
	# At least 4 out of 5 checks must be successful
	# to mark the backend as healthy
	.window = 5;
	.threshold = 4;
	.expected_response = 200;
}

<%- @backends.each_pair do | name, property | -%>
backend <%= name %> {
	.host = "127.0.0.1";
	.port = "<%= property['port'] %>";
<%- if property['probe'] -%>
	.probe = <%= property['probe'] %>;
<%- end -%>
}
<%- end -%>

# Initialise vcl
sub vcl_init {
	new mediawiki = directors.random();
<%- @backends.each_pair do | name, property | -%>
<%- if property['pool'] -%>
	mediawiki.add_backend(<%= name %>, 1);
<%- end -%>
<%- end -%>
}

# Purge ACL
acl purge {
	"localhost";
	# IPv6
	"2a10:6740::6/64";
	# IPv4
	"31.24.105.128/28";
}

# Cookie handling logic
sub evaluate_cookie {
	# Replace all session/token values with a non-unique global value for caching purposes.
	if (req.restarts == 0) {
		unset req.http.X-Orig-Cookie;
		if (req.http.Cookie) {
			set req.http.X-Orig-Cookie = req.http.Cookie;
			if (req.http.Cookie ~ "([Ss]ession|Token)=") {
				set req.http.Cookie = "Token=1";
			} else {
				unset req.http.Cookie;
			}
		}
	}
}

# Mobile detection logic
sub mobile_detection {
	# If the User-Agent matches the regex (this is the official regex used in MobileFrontend for automatic device detection), 
	# and the cookie does NOT explicitly state the user does not want the mobile version, we
	# set X-Device to phone-tablet. This will make vcl_backend_fetch add ?useformat=mobile to the URL sent to the backend.
	if (req.http.User-Agent ~ "(?i)(mobi|240x240|240x320|320x320|alcatel|android|audiovox|bada|benq|blackberry|cdm-|compal-|docomo|ericsson|hiptop|htc[-_]|huawei|ipod|kddi-|kindle|meego|midp|mitsu|mmp\/|mot-|motor|ngm_|nintendo|opera.m|palm|panasonic|philips|phone|playstation|portalmmm|sagem-|samsung|sanyo|sec-|semc-browser|sendo|sharp|silk|softbank|symbian|teleca|up.browser|vodafone|webos)" && req.http.Cookie !~ "(stopMobileRedirect=true|mf_useformat=desktop)") {
		set req.http.X-Device = "phone-tablet";

		# In vcl_backend_fetch we'll decide in which situations we should actually do something with this.
		set req.http.X-Use-Mobile = "1";
	} else {
		set req.http.X-Device = "desktop";
	}
}

# Rate limiting logic
sub rate_limit {
	# Allow higher limits for static.mh.o, we can handle more of those requests
	if (req.http.Host == "static.miraheze.org") {
		if (vsthrottle.is_denied("static:" + req.http.X-Real-IP, 500, 1s)) {
			return (synth(429, "Varnish Rate Limit Exceeded"));
		}
	} else {
		# Do not limit /w/load.php, /w/resources, /favicon.ico, etc
		# T6283: remove rate limit for IABot (temporarily?)
		if (
			(req.url ~ "^/wiki" || req.url ~ "^/w/(api|index)\.php")
			&& (req.http.X-Real-IP != "185.15.56.22" && req.http.User-Agent !~ "^IABot/2")
		) {
			if (req.url ~ "^/w/index\.php\?title=\S+\:MathShowImage&hash=[0-9a-z]+&mode=mathml") {
				# The Math extension at Special:MathShowImage may cause lots of requests, which should not fail
				if (vsthrottle.is_denied("math:" + req.http.X-Real-IP, 120, 10s)) {
					return (synth(429, "Varnish Rate Limit Exceeded"));
				}
			} else {
				# Fallback
				if (vsthrottle.is_denied("mwrtl:" + req.http.X-Real-IP, 12, 2s)) {
					return (synth(429, "Varnish Rate Limit Exceeded"));
				}
			}
		}
	}
}

# Artificial error handling/redirects within Varnish
sub vcl_synth {
	if (resp.status == 752) {
		set resp.http.Location = resp.reason;
		set resp.status = 302;
		return (deliver);
	}

	if (resp.reason == "healthcheck") {
		set resp.reason = "OK";
		synthetic("Varnish is running on <%= @hostname %>");
	}

	// Handle CORS preflight requests
	if (
		req.http.Host == "static.miraheze.org" &&
		resp.reason == "CORS Preflight"
	) {
		set resp.reason = "OK";
		set resp.http.Connection = "keep-alive";
		set resp.http.Content-Length = "0";

		// allow Range requests, and avoid other CORS errors when debugging with X-Miraheze-Debug
		set resp.http.Access-Control-Allow-Origin = "*";
		set resp.http.Access-Control-Allow-Headers = "Range,X-Miraheze-Debug";
		set resp.http.Access-Control-Allow-Methods = "GET, HEAD, OPTIONS";
		set resp.http.Access-Control-Max-Age = "86400";
	}
}

# Purge Handling
sub recv_purge {
	if (req.method == "PURGE") {
		if (!client.ip ~ purge) {
			return (synth(405, "Denied."));
		} else {
			return (purge);
		}
	}
}

# Main MediaWiki Request Handling
sub mw_request {
	call rate_limit;
	call mobile_detection;
	
	# Assigning a backend
	if (
		req.url ~ "^/\.well-known" ||
		req.http.Host == "sslrequest.miraheze.org"
	) {
		set req.backend_hint = mwtask111;
		return (pass);
	} else {
		set req.backend_hint = mediawiki.backend();
	}

	# Numerous static.miraheze.org specific code
	if (req.http.Host == "static.miraheze.org") {
		# We can do this because static.mh.o should not be capable of serving such requests anyway
		# This could also increase cache hit rates as Cookies will be stripped entirely
		unset req.http.Cookie;
		unset req.http.Authization;

		# Normalise thumb URLs to prevent capitalisation or odd casing duplicating numerous resources
		# set req.url = regsub(req.url, "^(.+/)[^/]+$", "\1") + std.tolower(regsub(req.url, "^.+/([^/]+)$", "\1"));

		# CORS Prelight
		if (req.method == "OPTIONS" && req.http.Origin) {
			return (synth(200, "CORS Preflight"));
		}
	}

	# Don't cache a non-GET or HEAD request
	if (req.method != "GET" && req.method != "HEAD") {
		# Zero reason to append ?useformat=true here
		set req.http.X-Use-Mobile = "0";
		return (pass);
	}

	# If a user is logged out, do not give them a cached page of them logged in
	if (req.http.If-Modified-Since && req.http.Cookie ~ "LoggedOut") {
		unset req.http.If-Modified-Since;
	}

	# Don't cache certain things on static
	if (
		req.http.Host == "static.miraheze.org" &&
		(
			req.url !~ "^/.*wiki" || # If it isn't a wiki folder, don't cache it
			req.url ~ "^/(.+)wiki/sitemaps" || # Do not cache sitemaps
			req.url ~ "^/.*wiki/dumps" # Do not cache wiki dumps
		)
	) {
		return (pass);
	}

	# We can rewrite those to one domain name to increase cache hits
	if (req.url ~ "^/w/(skins|resources|extensions)/" ) {
		set req.http.Host = "meta.miraheze.org";
	}

	# api & rest.php are not safe when cached
	if (req.url ~ "^/w/(api|rest).php/.*" ) {
		return (pass);
	}

	# A requet via OAuth should not be cached or use a cached response elsewhere
	if (req.http.Authorization ~ "OAuth") {
		return (pass);
	}

	# GDNSD checks
	if (req.url ~ "^/healthcheck$") {
		set req.http.Host = "login.miraheze.org";
		set req.url = "/wiki/Main_Page";
		return (pass);
	}

	call evaluate_cookie;
}

# Initial sub route executed on a Varnish request, the heart of everything
sub vcl_recv {
	call recv_purge; # Check purge

	unset req.http.Proxy; # https://httpoxy.org/

	# Health checks, do not send request any further, if we're up, we can handle it
	if (req.http.host == "health.miraheze.org" && req.url == "/check") {
		return (synth(200, "healthcheck"));
	}

	# Normalise Accept-Encoding for better cache hit ratio
	if (req.http.Accept-Encoding) {
		if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
			# No point in compressing these
			unset req.http.Accept-Encoding;
		} elsif (req.http.Accept-Encoding ~ "gzip") {
			set req.http.Accept-Encoding = "gzip";
		} elsif (req.http.Accept-Encoding ~ "deflate") {
			set req.http.Accept-Encoding = "deflate";
		} else {
			# We don't understand this
			unset req.http.Accept-Encoding;
		}
	}

	# Only cache js files from Matomo
	if (req.http.Host == "matomo.miraheze.org") {
		set req.backend_hint = mon111;

		# Yes, we only care about this file
		if (req.url ~ "^/piwik.js" || req.url ~ "^/matomo.js") {
			return (hash);
		} else {
			return (pass);
		}
	}

	# Do not cache requests from this domain
	if (req.http.Host == "icinga.miraheze.org" || req.http.Host == "grafana.miraheze.org") {
		set req.backend_hint = mon111;

		return (pass);
	}

	# Do not cache requests from this domain
	if (req.http.Host == "phabricator.miraheze.org" || req.http.Host == "phab.miraheze.wiki" ||
            req.http.Host == "blog.miraheze.org") {
		set req.backend_hint = phab121;
		return (pass);
	}

	# Do not cache requests from this domain
	if (req.http.Host == "webmail.miraheze.org") {
		set req.backend_hint = mail121;
		return (pass);
	}

	# MediaWiki specific
	call mw_request;

	return (hash);
}

# Defines the uniqueness of a request
sub vcl_hash {
	# FIXME: try if we can make this ^/wiki/ only?
	if (req.url ~ "^/wiki/" || req.url ~ "^/w/load.php") {
		hash_data(req.http.X-Device);
	}
}

# Initiate a backend fetch
sub vcl_backend_fetch {
	# Modify the end of the URL if mobile device
	if ((bereq.url ~ "^/wiki/[^$]" || bereq.url ~ "^/w/index.php(.*)title=[^$]") && bereq.http.X-Device == "phone-tablet" && bereq.http.X-Use-Mobile == "1") {
		if (bereq.url ~ "\?") {
			set bereq.url = bereq.url + "&useformat=mobile";
		} else {
			set bereq.url = bereq.url + "?useformat=mobile";
		}
	}
	
	# Restore original cookies
	if (bereq.http.X-Orig-Cookie) {
		set bereq.http.Cookie = bereq.http.X-Orig-Cookie;
		unset bereq.http.X-Orig-Cookie;
	}
}

# Backend response, defines cacheability
sub vcl_backend_response {
	# Cookie magic as we did before
	if (bereq.http.Cookie ~ "([Ss]ession|Token)=") {
		set bereq.http.Cookie = "Token=1";
	} else {
		unset bereq.http.Cookie;
	}

	# A hit-for-pass action
	if (beresp.ttl <= 0s) {
		set beresp.ttl = 1800s;
		set beresp.uncacheable = true;
	}
	
	# Distribute caching re-calls where possible
	if (beresp.ttl >= 60s) {
		set beresp.ttl = beresp.ttl * std.random( 0.95, 1.00 );
	}

	# Do not cache a backend response if HTTP code is above 400, except a 404, then limit TTL
	if (beresp.status >= 400 && beresp.status != 404) {
		set beresp.uncacheable = true;
	} elseif (beresp.status == 404 && beresp.ttl > 10m) {
		set beresp.ttl = 10m;
	}

	# If we have a cookie, we can't cache it, unless we can?
	# We can cache when cookies are stripped, and no other cookies are present
	if (
		bereq.http.Cookie == "Token=1"
		&& beresp.http.Vary ~ "(?i)(^|,)\s*Cookie\s*(,|$)"
	) {
		return(pass(607s));
	} elseif (beresp.http.Set-Cookie) {
		set beresp.uncacheable = true; # We do this just to be safe - but we should probably log this to eliminate it?
	}

	# Cache 301 redirects for 12h (/, /wiki, /wiki/ redirects only)
	if (beresp.status == 301 && bereq.url ~ "^/?(wiki/?)?$" && !beresp.http.Cache-Control ~ "no-cache") {
		set beresp.ttl = 43200s;
	}

	return (deliver);
}

# Last sub route activated, clean up of HTTP headers etc.
sub vcl_deliver {
	# We set Access-Control-Allow-Origin to * for all files hosted on
	# static.miraheze.org. We also set this header for some images hosted
	# on the same site as the wiki (private).
	if (
		req.http.Host == "static.miraheze.org" ||
		req.url ~ "(?i)\.(gif|jpg|jpeg|pdf|png|css|js|json|woff|woff2|svg|eot|ttf|otf|ico|sfnt|stl|STL)$"
	) {
		set resp.http.Access-Control-Allow-Origin = "*";
	}

	if (req.url ~ "^/wiki/" || req.url ~ "^/w/index\.php") {
		// ...but exempt CentralNotice banner special pages
		if (req.url !~ "^/(wiki/|w/index\.php\?title=)Special:Banner") {
			set resp.http.Cache-Control = "private, s-maxage=0, max-age=0, must-revalidate";
		}
	}

	# Client side caching for load.php
	if (req.url ~ "^/w/load\.php" ) {
		set resp.http.Age = 0;
	}

	# Do not index certain URLs
	if (req.url ~ "^(/w/(api|index|rest)\.php*|/wiki/Special(\:|%3A)(?!WikiForum)).+$") {
		set resp.http.X-Robots-Tag = "noindex";
	}

	# Useful debugging information
	if (obj.hits > 0) {
		set resp.http.X-Cache = "<%= scope.lookupvar('::hostname') %> HIT (" + obj.hits + ")";
	} else {
		set resp.http.X-Cache = "<%= scope.lookupvar('::hostname') %> MISS (0)";
	}

	# Disable Google ad targeting (FLoC)
	set resp.http.Permissions-Policy = "interest-cohort=()";

	# Content Security Policy
	set resp.http.Content-Security-Policy = "<%- @csp_whitelist.each_pair do |type, value| -%> <%= type %> <%= value.join(' ') %>; <%- end -%>";

	# For a 500 error, do not set cookies
	if (resp.status >= 500 && resp.http.Set-Cookie) {
		unset resp.http.Set-Cookie;
	}

	return (deliver);
}

# Backend response when an error occurs
sub vcl_backend_error {
	set beresp.http.Content-Type = "text/html; charset=utf-8";

	synthetic( {"<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<meta name="description" content="Backend Fetch Failed">
			<title>"} + beresp.status + " " + beresp.reason + {"</title>
			<!-- Bootstrap core CSS -->
			<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
			<style>
				/* Error Page Inline Styles */
				body {
					padding-top: 20px;
				}
				/* Layout */
				.jumbotron {
					font-size: 21px;
					font-weight: 200;
					line-height: 2.1428571435;
					color: inherit;
					padding: 10px 0px;
				}
				/* Everything but the jumbotron gets side spacing for mobile-first views */
				.masthead, .body-content {
					padding-left: 15px;
					padding-right: 15px;
				}
				/* Main marketing message and sign up button */
				.jumbotron {
					text-align: center;
					background-color: transparent;
				}
				.jumbotron .btn {
					font-size: 21px;
					padding: 14px 24px;
				}
				/* Colors */
				.green {color:#5cb85c;}
				.orange {color:#f0ad4e;}
				.red {color:#d9534f;}
			</style>
			<script>
				function loadDomain() {
					var display = document.getElementById("display-domain");
					display.innerHTML = document.domain;
				}
			</script>
		</head>
		<div class="container">
			<!-- Jumbotron -->
			<div class="jumbotron">
				<h1><img src="https://upload.wikimedia.org/wikipedia/commons/b/b7/Miraheze-Logo.svg" alt="Miraheze Logo"> "} + beresp.status + " " + beresp.reason + {"</h1>
				<p class="lead">Our servers are having issues at the moment.</p>
				<a href="javascript:document.location.reload(true);" class="btn btn-lg btn-outline-success" role="button">Try this page again</a>
			</div>
		</div>
		<div class="container">
			<div class="body-content">
				<div class="row">
					<div class="col-md-6">
						<h2>What can I do?</h2>
						<p class="lead">If you're a wiki visitor or owner</p>
						<p>Try again in a few minutes. If the problem persists, please report this on <a href="https://phabricator.miraheze.org">phabricator.</a> We apologize for the inconvenience. Our sysadmins should be attempting to solve the issue ASAP!</p>
					</div>
					<div class="col-md-6">
						<a class="twitter-timeline" data-width="500" data-height="350" text-align: center href="https://twitter.com/miraheze?ref_src=twsrc%5Etfw">Tweets by miraheze</a> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
					</div>
				</div>
			</div>
		</div>

		<div class="footer">
			<div class="text-center">
				<p class="lead">When reporting this, please be sure to provide the information below.</p>

				Error "} + beresp.status + " " + beresp.reason + {", forwarded for "} + bereq.http.X-Forwarded-For + {" <br />
				(Varnish XID "} + bereq.xid + {") via "} + server.identity + {" at "} + now + {".
				<br /><br />
			</div>
		</div>
	</html>
	"} );

	return (deliver);
}
