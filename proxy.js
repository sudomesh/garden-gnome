var settings = require('./settings.js');

var _ = require('lodash');
var http = require('http');
var httpProxy = require('http-proxy');
var fs = require('fs-extra');
var url = require('url');
var requestIp = require('request-ip');

var staticSplashHtml = fs.readFileSync(__dirname + '/www/splash.html');

var configs = {};

var ipProbeRequests = [];
var cachedPathNames = [];

var addClearedIp;
var debug;

module.exports = {
  init: function(initConfigs, addClearedIpFunc, debugFunc) {
    _.extend(configs, initConfigs);
    addClearedIp = addClearedIpFunc;
    debug = debugFunc;
  },

  start: function() {

    var proxy = httpProxy.createProxyServer({});

    debug('proxyPort: ' + configs.proxyPort);
    var server = http.createServer(function(req, res) {

      var srcIp = requestIp.getClientIp(req);
      var parsedUrl = url.parse(req.url);
      debug('Received request for:');
      debug(parsedUrl);
      debug(req.url);
      debug('Headers:');
      debug(req.headers);
      debug('From source:');
      debug(srcIp);
      var matched = false;
      debug('ProbeRequests:');
      debug(settings.probeRequests.concat(ipProbeRequests));

      // See if this is a click to clear the captive portal
      var clicked = false;
      _.each(settings.clearIpHeaders, function(header) {
        _.each(header, function (value, key) {
          debug('ClearIpHeader:');
          debug('key = ' + key);
          debug('value = ' + value);
          if (typeof req.headers[key] !== 'undefined' &&
              req.headers[key] == value) {
            debug('header ' + key + ' matches.');
            clicked = true;
            debug('srcIp: ' + srcIp + ' being added to cleared IPs');
          }
        });
      });

      if (clicked) {
        addClearedIp(srcIp);

      } else {

        // If it matches one of our pre-set urls
        _.each(settings.probeRequests.concat(ipProbeRequests), function(probeUrl) {
          var parsedProbe = url.parse(probeUrl);
          if (parsedUrl.pathname === parsedProbe.pathname && 
              parsedProbe.host === req.headers.host) {
            debug(parsedUrl.pathname + ' matches ' + probeUrl);
            matched = true;
          } 
        });

        // Check to see if it matches one of our probe headers and if it does
        // save the host+pathname combination 
        _.each(settings.probeHeaders, function(header) {
          _.each(header, function (regex, key) {
            debug('ProbeHeader:');
            debug('key = ' + key);
            debug('regex = ' + regex);
            if (typeof req.headers[key] === 'string' &&
                regex.test(req.headers[key])) {
              debug(req.url + ' matches because header ' + req.headers[key] + ' matches.');
              matched = true;
              debug('saving pathname: ' + parsedUrl.host + '://' + parsedUrl.pathname + ' for ' + settings.cachePathnameTime + 'sec');

              cachedPathNames.push({
                host: parsedUrl.host,
                pathname: parsedUrl.pathname
              });

              setTimeout(function() {
                cachedPathNames = _.without(cachedPathNames, _.findWhere(cachedPathNames, {
                  host: parsedUrl.host,
                  pathname: parsedUrl.pathname
                }));
              }, settings.cachePathnameTime * 1000);
            }
          });
        });

        // Check to see if it matches one of the cached host/pathnames
        _.each(cachedPathNames, function(pathObj) {
          if (parsedUrl.host === pathObj.host && parsedUrl.pathname === pathObj.pathname) {
            matched = true;
          }
        });
      }

      if (matched && !clicked) {
        proxy.web(req, res, {
          target: 'http://' + configs.listenIp + ':' + configs.webPort
        });
      } else {
        debug('Proxying to target:');
        debug('http://' + req.headers.host + req.url);
        debug('From source:');
        debug(srcIp);

        proxy.web(req, res, {
          target: 'http://' + req.headers.host + req.url
        });
      }
    }).listen(configs.proxyPort, '0.0.0.0', function() {
      debug('listening on port ' + configs.proxyPort);
    });

    debug('webPort: ' + configs.webPort);

    http.createServer(function (req, res) {
      var parsedUrl = url.parse(req.url);
      debug('Received request for:');
      debug(parsedUrl);
      debug(req.url);
      debug(req.headers);
      res.writeHead(200, {'Content-Type': 'text/html' });
      res.write(staticSplashHtml);
      res.end();
    }).listen(configs.webPort, '127.0.0.1', function() {
      debug('listening on 127.0.0.1:' + configs.webPort);
    });
  }
};

