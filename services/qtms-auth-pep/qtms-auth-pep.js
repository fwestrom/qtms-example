'use strict';

var crutch = require('qtort-microservices').crutch;
var request = require('request');
var etlUsers = require('./integrationTest')

var defaults = {
    defaultExchange: 'topic://ep',
    defaultQueue: 'qtms-auth-pep',
    defaultReturnBody: false,
    id: 'qtms-auth-pep',
    identityServer: 'https://wso2is:9443',
    identityServerUser: 'admin',
    identityServerPassword: 'admin',
};

crutch(defaults, function(_, logging, microservices, options, Promise, util, xml2js, soap) {
    var log = logging.getLogger(options.id);
    xml2js = Promise.promisifyAll(xml2js);
    soap = Promise.promisifyAll(soap);
    let parseXml = Promise.promisify(xml2js.parseString);


    process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

    return Promise.all([
        microservices.bind('api.#', onMessage),
        microservices.bind('api-reply.#', onReply),
    ]);


    function checkBasicHeader(mc){

        if (!mc.properties.authorization) {
           throw new Error('authorization can not be null');
        }

        let body = mc.deserialize();
        var authHeader = mc.properties.authorization || '';
        var token=authHeader.split(/\s+/) || '';
        if (token.length < 2) {
            throw new Error('Please enter the valid authorization like Basic [token]');
        }

        var auth = new Buffer(_.last(token), 'base64').toString();
        var user = auth.split(/:/);
        if (user.length < 2) {
            throw new Error('Please enter the valid authorization');
        }

        var userName = _.first(user);
        var password = _.last(user);
        var clientHeader = _.get(mc, 'properties.x-qtort-test');
        var etlUser = _.find(etlUsers, function(usr){
            return (_.get(usr, 'auth.login') === userName) && (_.get(usr, 'auth.password') === password) && (_.get(usr, 'clientId') === clientHeader)
        })

        if(etlUser){
            var subject = 'x-qtort:v1:auth:subject:' + userName;

            mc.properties['auth-pep.original-reply-to'] = mc.properties.replyTo;
            mc.properties.replyTo = undefined;

            return microservices.send('topic://api/' + mc.routingKey, body, _.extend(mc.properties, {
                mandatory: true,
                auth: {
                    subject: subject,
                    qsUserId : etlUser.qsUserId
                },
                replyTo: options.defaultExchange + '/' + 'api-reply.' + mc.routingKey,
            }))
            .then(function(result) {
                mc.properties.replyTo = undefined;
                return undefined;
            });
        }
        else {
            return mc.reply({ status: { code: 401, message: 'Unauthorized' } }, {}).return(undefined);
        }
    }

    function onMessage(mc) {
        let body = mc.deserialize();
        log.trace('onMessage|\n mc:\n', mc, '\n body:\n', body);

        _.forEach({
            bypass: _.get(mc.properties, 'pep.bypass'),
        }, _.rearg(_.partial(_.set, request), 1, 0));

        var bypass = _.get(request, 'pep.bypass') ? request.pep.bypass : false;

        var authToken = _.get(/[Bb]earer\s+([^\s]*)/.exec(mc.properties.authorization || ''), 1) || undefined;

        log.trace('onMessage| auth-token: %s', authToken);

        var user = _.get(mc, 'properties.authorization.user') || undefined;
        var pass = _.get(mc, 'properties.authorization.pass') || undefined;


        /*for checking the different-different client*/
        var clientHeader = _.get(mc, 'properties.x-qtort-test');
        if(clientHeader){

            //if(clientHeader ==='20380a36-8777-43f7-a79e-65bdb53f4621'){
            checkBasicHeader(mc);
            return;
            /*}
            else {
                return { status: { code: 401, message: 'Unauthorized : Client Id in invalid' } };
            }*/

        }

        if(!authToken){
             return { status: { code: 401, message: 'Unauthorized' } };
        }

        var userinfoRequestOptions = !authToken ? null : {
            url: options.identityServer + '/oauth2/userinfo?schema=openid&scope=openid',
            method: 'GET',
            strictSSL: false,
            auth: { bearer: authToken },
        };

        log.trace('onMessage| userinfoRequestOptions:\n%s', util.inspect(userinfoRequestOptions));
        return (!userinfoRequestOptions
            ? Promise.resolve({})
            : new Promise(function(resolve, reject) {
                request(userinfoRequestOptions, function(error, response, body) {
                    return error ? reject(error) : resolve(JSON.parse(body)); //reject({ status: { code: CODE_GOES_HERE_TYPE_INT, message: 'Message here if applicable' }});
                });
            }))
            .then(function(userInfo) {
                var subject = 'x-qtort:v1:auth:subject:' + _.get(userInfo, 'sub');
                log.trace('onMessage| subject: %s, \nuserInfo:\n', subject, userInfo);

                // added the user information for the user
                mc.properties['auth-pep.original-user'] = userInfo;

                return mapUserPermission(userInfo, mc.properties.url, mc.properties.method)
                    .then(function(result) {

                        mc.properties['auth-pep.original-reply-to'] = mc.properties.replyTo;
                        mc.properties.replyTo = undefined;

                        //return mapQsUser(userInfo, mc).then(function(){
                            return microservices.send('topic://api/' + mc.routingKey, body, _.extend(mc.properties, {
                                    mandatory: true,
                                    auth: {
                                        subject: subject,
                                    },
                                    replyTo: options.defaultExchange + '/' + 'api-reply.' + mc.routingKey,
                                }))
                                .then(function() {
                                    mc.properties.replyTo = undefined;
                                    return undefined;
                                });
                        //})
                    });
            })
            .catch(function(error) {
                log.warn('error|', inspect(error));
                return mc.reply(error, {
                    'status.code': _.get(error, 'status.code') || 500,
                    'status.message': _.get(error, 'status.message') || 'Unexpected Failure',
                }).return(undefined);
            });
    };

    function onReply(mc) {
        log.trace('onReply| mc:\n', mc);
        var userInfo = mc.properties['auth-pep.original-user'];
        return Promise
            .try(function(){
                var links = _.get(mc, 'properties.links');

                var linkArray = [];
                _.forEach(links, function(value, key){
                    linkArray.push(_.replace(_.get(value, 'to'), /[.]/g, '/'));
                })

                var clientHeader = _.get(mc, 'properties.x-qtort-test');
                if(clientHeader){
                    var result = mc.deserialize();
                    return result;
                }

               else{
                    return mapUserPermission(userInfo, links, mc.properties.method)
                    .then(function(result) {
                        return result;
                    });
               }

            })
            .then(result => {
                return microservices.send(
                mc.properties['auth-pep.original-reply-to'],
                mc.body,
                _.omit(mc.properties, ['replyTo', 'auth-pep.original-reply-to', 'auth-pep.original-user'],
                { mandatory: true }))
                .return(undefined);
            })

    }


    function mapUserPermission(userInfo, link, method){

        //var testLinks = ['api/org-unit']

        return getSoapClient(options.identityServer + '/services/EntitlementService')
            .then(function(client) {
                return client.getDecisionByAttributesAsync({ subject: userInfo.sub || userInfo.preferred_username, resource: ['/api'], action: method.toLowerCase() })
               .catch(function(error) {
                   if (error.message == 'Cannot parse response') {
                       return parseXml(error.body);
                   }
                   throw error;
               })
               .then(function(result) {
                   log.trace('get-decision| result:', result);
                   if (_.get(result, 'faultstring')) {
                       throw { status: { code: 500, message: result.faultstring, cause: result } }
                   }
                   var results = _.first(_.values(_.omit(_.first(_.values(result)), '$')));
                   return parseXml(_.first(results));
               })
               .then(function(result){
                    log.trace('result:', util.inspect(result, { depth: null, colors: true }));

                       if (_.get(result, 'Response.Result[0].Decision[0]') != 'Permit') {
                            throw {
                                status: {
                                    code: 401,
                                    message: 'Unauthorized',
                                },
                            };
                        }
               });
            });
    }

/*    function mapQsUser(userInfo, mc){

        var userName = userInfo.sub || userInfo.preferred_username;
        var user = _.first(_.split(_.last(_.split(userName, '/')), '@'));

        log.debug('mapQsUser| map the user:', user);
        return microservices.call('topic://api/api.auth.users.'+ user +'.qtort.post', _.extend(mc.properties, {
            replyTo: options.defaultExchange + '/' + 'api-reply.' + mc.routingKey,
        })).then(function(res) {
            return res;
        });
    }*/

    function getSoapClient(url) {
        var promises = getSoapClient.promises || (getSoapClient.promises = {});
        if (!_.has(promises, url)) {
            log.debug('getSoapClient| creating new soap client; url:', url);
            promises[url] = soap.createClientAsync(url + '?wsdl')
                .then(function(client) {
                    client.setEndpoint(url);
                    client.setSecurity(new soap.BasicAuthSecurity(options.identityServerUser, options.identityServerPassword));
                    return Promise.promisifyAll(client);
                });
        }
        return promises[url];
    }

    function inspect(value, showHidden) {
        return util.inspect(value, _.extend({
            colors: true,
            depth: null,
            showHidden: showHidden,
        }));
    }
});
