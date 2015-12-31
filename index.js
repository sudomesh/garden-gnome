#!/usr/bin/env node

var argv = require('yargs').argv;
var exec = require('child_process').exec;
var fs = require('fs-extra');
var http = require('http');
var httpProxy = require('http-proxy');
var _ = require('underscore');
var iptables = require('netfilter').iptables;
var ps = require('ps-node');
var url = require('url');
var dns = require('dns');
var Promise = require('promise');

var settings = require('./settings.js');

var listenIp = argv.ip || settings.listenIp;
var proxyPort = argv.proxyPort || settings.proxyPort;
var webPort = argv.webPort || settings.webPort;
var portalTime = argv.portalTime || settings.portalTime;
var dnsLookupPeriod = argv.dnsLookupPeriod || settings.dnsLookupPeriod;
var inInterface = argv.inInterface || settings.inInterface;

var ipProbeRequests = [];
var cachedPathNames = [];

var debug = function(str) {
  if (argv.debug) {
    process.stdout.write('[DEBUG] ');
    console.log(str);
  }
};

var usage = function() {
  console.error('');
  console.error('Usage: ' + __filename);
  console.error('');
  console.error('Options:');
  console.error('  --port <port>: port that the garden-gnome proxy will listen on');
  console.error('  --ip <ip>: ip that the port will listen on. Defaults to ' + settings.listenIp);
  console.error('  --portalTime <time>: amount of time before the portal is shown again (in min). Defaults to ' + settings.portalTime);
  console.error('  --dnsLookupPeriod <time>: amount of time before refreshing the dns cache (in sec). Defaults to ' + settings.dnsLookupPeriod);
  console.error('');
  console.error('Defaults can be overwritten in the settings.js file.');
  console.error('');
};

var checkDependencies = function(callback) {
  exec('dnsmasq --help').on('exit', function(code, signal) {
    if (code !== 0) {
      console.error('This program depends on dnsmasq for dns handling.');
      console.error('On Debian/Ubuntu systems you can install dnsmasq using:');
      console.error('');
      console.error('  sudo apt-get install dnsmasq');
      console.error('');
      callback('Dependency check failed');
      return;
    }

    debug('dnsmasq installed');
    
    ps.lookup({
      command: 'dnsmasq'
    }, function(err, resultList) {
      debug('ps lookup for dnsmasq:');
      debug(resultList);
      if (err) {
        debug('dnsmasq not running');
        callback('dnsmasq not running');
      }
      debug('dnsmasq running');
      callback(null);
    });
  });
};

var cleanup = function(callback) {
  return new Promise(function(resolve, reject) {
    iptables.delete({
      table: 'nat',
      chain: 'PREROUTING',

      protocol: 'tcp',
      source: settings.sourceNet,

      'destination-port': 80,
      'in-interface': settings.inInterface || undefined,

      jump: settings.iptablesChain
    }, function (err) {

      if (err) {
        debug(err);
        debug(settings.iptablesChain + ' PREROUTING rule already deleted?');
      } else {
        debug(settings.iptablesChain + ' PREROUTING rule deleted');
      }

      iptables.flush({
        table: 'nat',
        chain: settings.iptablesChain
      }, function (err) {
        iptables.deleteChain({
          table: 'nat',
          chain: settings.iptablesChain,
        }, function (err) {
          if (err) {
            debug(err);
            debug(settings.iptablesChain + ' chain already deleted?');
          } else {
            debug(settings.iptablesChain + ' chain deleted');
          }
          fs.truncateSync(settings.dnsmasqConfFile);
          resolve();
        });
      });
    });
  });
};

var refreshDnsmasq = function(callback) {
  dns.setServers(settings.dnsServers);
  fs.open(settings.dnsmasqConfFile, 'w', 0644, function(err, fd) {
    if (err) {
      callback(err);
      return;
    }

    var flushIptablesRulePromise = new Promise(function(resolve, reject) {
      try {
        iptables.flush({
          table: 'nat',
          chain: settings.iptablesChain,

        }, function (err) {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      } catch (e) {
        console.error('rejecting with error: ' + e.stack);
        reject(e);
      }
    });

    flushIptablesRulePromise.then(function() {

      var configBuffer = '';
      ipProbeRequests = [];

      var addIptablesRulePromises = [];
      _.each(settings.probeRequests, function(probeUrl) {
        addIptablesRulePromises.push(function() {
          return new Promise(function(resolve, reject) {
            try {

              var parsed = url.parse(probeUrl);

              debug('Resolving:');
              debug(parsed.hostname);

              dns.resolve(parsed.hostname, 'A', function(err, addresses) {
                if (err) {
                  reject('problem resolving ' + parsed.hostname + ' : ' + err);
                } else if (addresses.length === 0) {
                  reject('problem resolving ' + parsed.hostname + ' : no records returned');
                }

                var iptablesPromises = [];
                _.each(addresses, function(address) {
                  iptablesPromises.push(function() {
                    return new Promise(function (resolve, reject) {
                      configBuffer += 'host-record=' + parsed.hostname + ',' + address + '\n';
                      ipProbeRequests.push('http://' + address + parsed.pathname);
                      iptables.append({
                        table: 'nat',
                        chain: settings.iptablesChain,

                        protocol: 'tcp',
                        destination: address,
                        'destination-port': 80,

                        'in-interface': inInterface || undefined,

                        jump: 'REDIRECT',
                        target_options: {
                          'to-ports': proxyPort
                        }
                      }, function (err) {
                        if (err) {
                          reject(err);
                        } else {
                          resolve();
                        }
                      });
                    });
                  }());
                });
                Promise.all(iptablesPromises).then(function() {
                  debug('iptables rules appended');
                  resolve();
                }, function (err) {
                  reject(err);
                });
              });
            } catch (e) {
              reject(e);
            }
          });
        }());
      });

      Promise.all(addIptablesRulePromises).then(function() {
        debug('dnsmasq config buffer:');
        debug(configBuffer);

        fs.write(fd, configBuffer, function(err, written, string) {
          if (err) {
            callback('problem writing to dnsmasq config file: ' + err);
            return;
          } else {
            exec('service dnsmasq restart').on('exit', function(code, signal) {
              if (code !== 0) {
                console.error('failure restarting dnsmasq');
                callback('Dependency check failed');
                return;
              } else {
                callback();
              }
            });
          }
        });
      }, function (err) {
        callback(err);
      });
    }, function (err) {
      callback(err);
    });
  });
};

var run = function() {

  cleanup().then(function() {
    checkDependencies(function(err) {
      if (err) {
        console.error('Error: ' + err);
        process.exit();
      }

      iptables.new({
        table: 'nat',
        chain: settings.iptablesChain,
      }, function (err) {
        if (err) {
          console.error('Error: ' + err);
          process.exit();
        }

        iptables.append({
          table: 'nat',
          chain: 'PREROUTING',

          protocol: 'tcp',
          source: settings.sourceNet,
          'destination-port': 80,

          'in-interface': settings.inInterface || undefined,

          jump: settings.iptablesChain
        }, function (err) {
          if (err) {
            console.error('Error: ' + err);
          }

          refreshDnsmasq(function(err) {
            if (err) {
              console.error('Error: ' + err);
              process.exit();
            }
          });

          // Refresh dnsmasq file every dnslookupPeriod * 1000 ms
          setInterval(refreshDnsmasq, dnsLookupPeriod * 1000, function(err) {
            if (err) {
              console.error('Error: ' + err);
            }
          });

          var proxy = httpProxy.createProxyServer({});

          debug('proxyPort: ' + proxyPort);
          var server = http.createServer(function(req, res) {

            var parsedUrl = url.parse(req.url);
            debug('Received request for:');
            debug(parsedUrl);
            debug(req.url);
            debug('Headers:');
            debug(req.headers);
            debug('From source:');
            debug(req.connection.remoteAddress);
            var matched = false;
            debug('ProbeRequests:');
            debug(settings.probeRequests.concat(ipProbeRequests));

            // If it matches one of our pre-set urls
            _.each(settings.probeRequests.concat(ipProbeRequests), function(probeUrl) {
              var parsedProbe = url.parse(probeUrl);
              if (parsedUrl.pathname === parsedProbe.pathname && 
                  parsedProbe.host === req.headers.host) {
                debug(parsedUrl.pathname + ' matches ' + probeUrl);
                matched = true;
              } 
            });

            // Check to see if it matches one of our headers and if it does
            // save the host+pathname combination 
            _.each(settings.probeHeaders, function(regex, key) {
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

            // Check to see if it matches one of the cached host/pathnames
            _.each(cachedPathNames, function(pathObj) {
              if (parsedUrl.host === pathObj.host && parsedUrl.pathname === pathObj.pathname) {
                matched = true;
              }
            });

            if (matched) {
              proxy.web(req, res, {
                target: 'http://' + listenIp + ':' + webPort
              });
            } else {
              debug('Proxying to target:');
              debug('http://' + req.headers.host + req.url);
              debug('From source:');
              debug(req.connection.remoteAddress);

              proxy.web(req, res, {
                target: 'http://' + req.headers.host + req.url
              });
            }
          }).listen(proxyPort, function() {
            debug('listening on port ' + proxyPort);
          });

          debug('webPort: ' + webPort);

          http.createServer(function (req, res) {
            var parsedUrl = url.parse(req.url);
            debug('Received request for:');
            debug(parsedUrl);
            debug(req.url);
            debug(req.headers);
            res.writeHead(200, {'Content-Type': 'text/html' });
            res.write('<html><head><title>splash page</title></head><body><p>request successfully proxied to: ' + req.url + '\n' + JSON.stringify(req.headers, true, 2) + '</p></body></html>');
            res.end();
          }).listen(webPort, '127.0.0.1', function() {
            debug('listening on 127.0.0.1:' + webPort);
          });
        });
      });
    });
  }, function(err) {
    console.error('Error: ' + err);
  });
};

if (argv.help || argv.h) {
  usage();
  process.exit();
}

run();
