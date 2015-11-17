/**
 * Module dependencies.
 */

var _ = require('lodash');
var merge = require('utils-merge');
var querystring = require('querystring');
var url = require('url');
var util = require('util');
var utils = require('./utils');
var OAuth = require('oauth').OAuth;
var OAuthStrategy = require('passport-oauth').OAuthStrategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * Const parameters
 */
var DESK_COM_TOKEN_PATH = '/oauth/request_token';
var DESK_COM_ACCESS_TOKEN_PATH = '/oauth/access_token';
var DESK_COM_AUTH_PATH = '/oauth/authorize';
var DESK_CREDENTIAL_PATH = '/api/v2/users/me';

var DESK_COM_SESSION_KEY = 'oauth:deskcom:';

/**
 * `Strategy` constructor.
 *
 * Desk.com authentication strategy
 * Oauth1.0a protocol
 *
 * Options:
 *   - `consumerKey`     identifies client to Deskcom
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Deskcom will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *   passport.use(new DeskcomStrategy({
 *       consumerKey: '*************',
 *       consumerSecret: '***************',
 *       site: 'https://yoursite.desk.com',
 *     },
 *     function (token, tokenSecret, profile, done) {
 *
 *     }
 *   });
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  var site = options.site || 'www.desk.com';

  options.deskSite = site;
  options.requestTokenURL = options.requestTokenURL || site + DESK_COM_TOKEN_PATH;
  options.accessTokenURL = options.accessTokenURL || site + DESK_COM_ACCESS_TOKEN_PATH;
  options.userAuthorizationURL = options.userAuthorizationURL || site + DESK_COM_AUTH_PATH;
  options.sessionKey = options.sessionKey || DESK_COM_SESSION_KEY;

  OAuthStrategy.call(this, options, verify);
  this._options = options;
  this.name = 'deskcom';
}

util.inherits(Strategy, OAuthStrategy);

/**
 * Cache a separate OAuth client for each Desk site
 */
Strategy.prototype._oauthMap = {};
Strategy.prototype._createOauth = function(requestTokenURL, accessTokenURL, consumerKey,
                                           consumerSecret, signatureMethod, customHeaders) {
  return new OAuth(requestTokenURL, accessTokenURL, consumerKey,
                   consumerSecret, '1.0', null, signatureMethod || 'HMAC-SHA1', null,
                   customHeaders);
};
Strategy.prototype._oauthForSite = function(deskSite) {
  var options = this._options;
  var baseUrl = '';
  var requestTokenURL = deskSite + DESK_COM_TOKEN_PATH;
  var accessTokenURL = deskSite + DESK_COM_ACCESS_TOKEN_PATH;
  var userAuthorizationURL = deskSite + DESK_COM_AUTH_PATH;

  if (!this._oauthMap[deskSite]) {
    this._oauthMap[deskSite] = new OAuth(requestTokenURL, accessTokenURL, options.consumerKey, options.consumerSecret,
                                         '1.0', null, 'HMAC-SHA1', null);
  }

  return this._oauthMap[deskSite];
};

/**
 * Authenticate request by delegating to Desk.com using OAuth.
 *
 * @param req
 * @param options
 * @return {*}
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  if (req.query && req.query.denied)
    return this.fail();

  var bodyObj = req.body && querystring.parse(req.body);

  // Look for the subdomain to be specified in (in order of priority):
  //   1. authenticate options
  //   2. query string
  //   3. post body
  //   4. saved in the req.session from a previous request
  //   5. specified in strategy options
  // Additionally, cases 1,2,3 override 4 and 5
  options = options || {};
  var deskSite = options.deskSite || options.site ||
             (req.query && req.query.site) ||
             (bodyObj && bodyObj.site);

  if (deskSite) {
    if (req.session) {
      req.session.deskSite = deskSite;
    }
  } else {
    deskSite = (req.session && req.session.deskSite) ? req.session.deskSite : this._options.deskSite;
  }

  if (!deskSite) {
    return this.error(new Error('A Desk site was not specified in options and was not found in request parameters'));
  }

  var oauth = this._oauthForSite(deskSite);
  var profileEndpoint = deskSite + DESK_CREDENTIAL_PATH;

  // The remainder of this function was lifted from passport-oauth 1.0.0 with minor tweaks to fn calls & params passing
  if (!req.session) {
    return this.error(
      new Error('OAuthStrategy requires session support. Did you forget app.use(express.session(...))?')
    );
  }

  var self = this;

  if (req.query && req.query.oauth_token) {
    // The request being authenticated contains an oauth_token parameter in the
    // query portion of the URL.  This indicates that the service provider has
    // redirected the user back to the application, after authenticating the
    // user and obtaining their authorization.
    //
    // The value of the oauth_token parameter is the request token.  Together
    // with knowledge of the token secret (stored in the session), the request
    // token can be exchanged for an access token and token secret.
    //
    // This access token and token secret, along with the optional ability to
    // fetch profile information from the service provider, is sufficient to
    // establish the identity of the user.

    // Bail if the session does not contain the request token and corresponding
    // secret.  If this happens, it is most likely caused by initiating OAuth
    // from a different host than that of the callback endpoint (for example:
    // initiating from 127.0.0.1 but handling callbacks at localhost).
    if (!req.session[self._key]) { return self.error(new Error('Failed to find request token in session')); }

    var oauthToken = req.query.oauth_token;
    var oauthVerifier = req.query.oauth_verifier || null;
    var oauthTokenSecret = req.session[self._key].oauth_token_secret;

    // NOTE: The oauth_verifier parameter will be supplied in the query portion
    //       of the redirect URL, if the server supports OAuth 1.0a.

    oauth.getOAuthAccessToken(oauthToken, oauthTokenSecret, oauthVerifier, function(err, token, tokenSecret, params) {
      if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

      // The request token has been exchanged for an access token.  Since the
      // request token is a single-use token, that data can be removed from the
      // session.
      delete req.session[self._key].oauth_token;
      delete req.session[self._key].oauth_token_secret;
      if (Object.keys(req.session[self._key]).length === 0) {
        delete req.session[self._key];
      }

      // prototype.useProfile needs extra domain info to acces the correct endpoint, so we append that to params object
      // This `params` section was added just for multi-domain strategy support
      params = params || {};
      params.deskSite = deskSite;
      params.profileEndpoint = profileEndpoint;

      self._loadUserProfile(token, tokenSecret, params, function(err, profile) {
        if (err) { return self.error(err); }

        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }

        try {
          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 6) {
              self._verify(req, token, tokenSecret, params, profile, verified);
            } else { // arity == 5
              self._verify(req, token, tokenSecret, profile, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 5) {
              self._verify(token, tokenSecret, params, profile, verified);
            } else { // arity == 4
              self._verify(token, tokenSecret, profile, verified);
            }
          }
        } catch (ex) {
          return self.error(ex);
        }
      });
    });
  } else {
    // In order to authenticate via OAuth, the application must obtain a request
    // token from the service provider and redirect the user to the service
    // provider to obtain their authorization.  After authorization has been
    // approved the user will be redirected back the application, at which point
    // the application can exchange the request token for an access token.
    //
    // In order to successfully exchange the request token, its corresponding
    // token secret needs to be known.  The token secret will be temporarily
    // stored in the session, so that it can be retrieved upon the user being
    // redirected back to the application.

    var params = this.requestTokenParams(options);
    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
    }
    params.oauth_callback = callbackURL;

    oauth.getOAuthRequestToken(params, function(err, token, tokenSecret, params) {
      if (err) { return self.error(self._createOAuthError('Failed to obtain request token', err)); }

      // NOTE: params will contain an oauth_callback_confirmed property set to
      //       true, if the server supports OAuth 1.0a.
      //       { oauth_callback_confirmed: 'true' }

      if (!req.session[self._key]) { req.session[self._key] = {}; }
      req.session[self._key].oauth_token = token;
      req.session[self._key].oauth_token_secret = tokenSecret;

      var parsed = url.parse(self._userAuthorizationURL, true);
      parsed.query.oauth_token = token;
      merge(parsed.query, self.userAuthorizationParams(options));
      delete parsed.search;
      var location = url.format(parsed);
      self.redirect(location);
    });
  }
};

/**
 * Retrieve user profile from Desk.com.
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  this._oauth.get(params.profileEndpoint, token, tokenSecret, function (err, body, res) {
    if (err)
      return done(new InternalOAuthError('failed to fetch user CREDENTIAL', err));

    try {
      var json = JSON.parse(body);
      var profile = _.clone(json);
      profile.provider = 'deskcom';
      profile.token = token;
      profile.tokenSecret = tokenSecret;
      profile._raw = body;
      profile._json = json;
      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

