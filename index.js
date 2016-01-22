#!/usr/bin/env node

var argv = require('yargs').argv;
var exec = require('child_process').exec;
var fs = require('fs-extra');
var _ = require('lodash');
var iptables = require('netfilter').iptables;
var ps = require('ps-node');
var url = require('url');
var dns = require('dns');
var Promise = require('promise');
var moment = require('moment');

var settings = require('./settings.js');

var proxy = require('./proxy.js');

var listenIp = argv.ip || settings.listenIp;
var proxyPort = argv.proxyPort || settings.proxyPort;
var webPort = argv.webPort || settings.webPort;
var dnsLookupPeriod = argv.dnsLookupPeriod || settings.dnsLookupPeriod;
var inInterface = argv.inInterface || settings.inInterface;
var checkClearedPeriod = argv.checkClearedPeriod || settings.checkClearedPeriod;

var clearedChain = settings.iptablesChain + '1';
var proxyChain = settings.iptablesChain + '2';

var clearedIps = [];

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

      jump: clearedChain

    }, function (err) {
      if (err) {
        debug(err);
        debug(clearedChain + ' rule already deleted?');
      } else {
        debug(clearedChain + ' rule deleted');
      }


      iptables.delete({
        table: 'nat',
        chain: clearedChain,

        jump: proxyChain

      }, function (err) {

        if (err) {
          debug(err);
          debug(proxyChain + ' rule already deleted?');
        } else {
          debug(proxyChain + ' rule deleted');
        }

        iptables.flush({
          table: 'nat',
          chain: proxyChain
        }, function (err) {
          iptables.deleteChain({
            table: 'nat',
            chain: proxyChain,
          }, function (err) {
            if (err) {
              debug(err);
              debug(proxyChain + ' chain already deleted?');
            } else {
              debug(proxyChain + ' chain deleted');
            }

            iptables.flush({
              table: 'nat',
              chain: clearedChain
            }, function (err) {
              iptables.deleteChain({
                table: 'nat',
                chain: clearedChain,
              }, function (err) {
                if (err) {
                  debug(err);
                  debug(clearedChain + ' chain already deleted?');
                } else {
                  debug(clearedChain + ' chain deleted');
                }

                try {
                  fs.removeSync(settings.dnsmasqConfFile);
                } catch (e) {
                  debug('Error removing dnsmasqConfFile - perhaps it doesn\'t already exist? Error: ' + e);
                }
                resolve();
              });
            });
          });
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
          chain: proxyChain,

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

      var probeUrls = [];

      var cnameResolutionPromises = [];
      _.each(settings.probeRequests, function(probeUrl) {
        var parsed = url.parse(probeUrl);
        probeUrls.push(parsed);
        cnameResolutionPromises.push(function() {
          return new Promise(function(resolve, reject) {
            debug('resolving CNAME for ' + parsed.hostname);
            try {
              dns.resolve(parsed.hostname, 'CNAME', function(err, cnames) {
                debug('err:');
                debug(err);

                debug('cname resolution finished for: ');
                debug(parsed.hostname);
                debug('cnames:');
                debug(cnames);
                if (err) {
                  console.error('problem resolving CNAME from ' + parsed.hostname + ' : ' + err);
                  resolve();
                } else {
                  _.each(cnames, function(cname) {
                    probeUrls.push(url.parse(parsed.protocol + '//' + cname + parsed.path));
                  });

                  debug('resolving...');

                  resolve();
                }
              });
            } catch (e) {
              console.error('caught error:');
              console.error(e);
              reject(e);
            }
          });
        }());
      });

      Promise.all(cnameResolutionPromises).then(function() {
        ipProbeRequests = [];
        var addIptablesRulePromises = [];
        _.each(probeUrls, function(probeUrl) {
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
                          chain: proxyChain,

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
        console.log(err);
        callback();
      });
    }, function (err) {
      callback(err);
    });
  });
};

var addClearedIp = function(srcIp) {
  iptables.insert({
    table: 'nat',
    chain: clearedChain,

    source: srcIp,

    jump: 'RETURN',
  }, function (err) {
    if (err) {
      console.error(err);
    } else {
      debug('Added ' + srcIp + ' to ' + clearedChain);
      clearedIps.push({
        srcIp: srcIp,
        time: moment().unix()
      });
    }
  });
};

var cleanupClearedIps = function(callback) {
  var matchedIp = function(match) {
    return match.time + settings.clearedTime < moment().unix();
  }

  _.each(clearedIps, function(match) {
    if (matchedIp(match)) {
      iptables.delete({
        table: 'nat',
        chain: clearedChain,

        source: match.srcIp,

        jump: 'RETURN'

      }, function (err) {
        if (err) {
          console.error(err);
          console.error('Can\'t delete iptables rule in ' + clearedChain + ' from srcIp = ' + match.srcIp);
          callback(err);
        } else {
          debug('Deleted iptables rule in ' + clearedChain + ' from srcIp = ' + match.srcIp);
        }
      });
    }
  });

  _.remove(clearedIps, matchedIp);
  callback();
};

var run = function() {
  proxy.init({
    listenIp: listenIp,
    proxyPort: proxyPort,
    webPort: webPort,
    proxyChain: proxyChain,
  }, addClearedIp, debug);

  cleanup().then(function() {
    checkDependencies(function(err) {
      if (err) {
        console.error('Error: ' + err);
        gracefulExit();
      }

      iptables.new({
        table: 'nat',
        chain: clearedChain,
      }, function (err) {
        if (err) {
          console.error('Error: ' + err);
          gracefulExit();
        }

        iptables.new({
          table: 'nat',
          chain: proxyChain,
        }, function (err) {
          if (err) {
            console.error('Error: ' + err);
            gracefulExit();
          }

          iptables.append({
            table: 'nat',
            chain: 'PREROUTING',

            protocol: 'tcp',
            source: settings.sourceNet,
            'destination-port': 80,

            'in-interface': settings.inInterface || undefined,

            jump: clearedChain
          }, function (err) {
            if (err) {
              console.error('Error: ' + err);
              gracefulExit();
            }

            iptables.append({
              table: 'nat',
              chain: clearedChain,

              jump: proxyChain
            }, function (err) {
              if (err) {
                console.error('Error: ' + err);
                gracefulExit();
              }

              refreshDnsmasq(function(err) {
                if (err) {
                  console.error('Error: ' + err);
                  gracefulExit();
                }
              });

              proxy.start();

              // Refresh dnsmasq file every dnslookupPeriod * 1000 ms
              setInterval(refreshDnsmasq, dnsLookupPeriod * 1000, function(err) {
                if (err) {
                  console.error('Error: ' + err);
                }
              });

              // Check for cleared ips every checkClearedPeriod * 1000ms
              setInterval(cleanupClearedIps, checkClearedPeriod * 1000, function(err) {
                if (err) {
                  console.error('Error: ' + err);
                }
              });

            });
          });
        });
      });
    });
  }, function(err) {
    console.error('Error: ' + err);
  });

  var gracefulExit = function() {
    cleanup().then(function() {
      process.exit();
    });
  };

  process.on('SIGINT', gracefulExit);
  process.on('SIGHUP', gracefulExit);
  process.on('SIGTERM', gracefulExit);

};

if (argv.help || argv.h) {
  usage();
  process.exit();
}

run();
