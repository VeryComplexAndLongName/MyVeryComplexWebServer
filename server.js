function Main() {
    var self = this;

    this._myModuleName = 'Main';
    this.moduleName = function() { return self._myModuleName; };
    this.ver = function() { return '0.0.1'; };
    this.appName = function() { return 'MyApp'; };
    this.txtDescr = function() { return 'This is universal application has a modular structure. In fact it provides API and login for create your own set of applications and separate them into a logical parts.'; };
    this.htmlDescr = function() { return '<h2>Not available yet</h2>'; };

    // =========== Start Server ================
    this.start = function() {
        // Throng
        self._throng({
            workers: self._os.cpus().length, // Number of workers (cpu count)
            master: self._startMaster, // Function to call when starting the master process
            start: self._startWorker, // Function to call when starting the worker processes
        });

        // Transaction support
        self._app.on(self._myConst.eventHandlerStarted, self._handlerStartedCallback);
        self._app.on(self._myConst.eventHandlerFinished, self._handlerFinishedCallback);
    };
    // =========================================

    // === External Modules start ===
    // Linq to JS Objects
    // https://jinqjs.readme.io/docs/what-is-jinqjs
    this._jinq = require('jinq');
    // Create SQL strings to  Postgres, MSSQL, MySQL
    // https://hiddentao.com/squel/
    this._squel = require('squel');
    // Clustering support
    this._throng = require('throng');
    // Web Server
    this._express = require('express');
    this._app = self._express();
    this._bodyParser = require('body-parser');
    // Basic authentication
    this._auth = require('basic-auth');
    // Path works
    this._path = require('path');
    // Http Status Codes
    this._httpStatus = require('http-status-codes');
    // Http Methods Names
    this._httpMethod = require('list-http-methods');
    // work with file system
    this._fs = require('fs');
    // OS
    this._os = require('os');
    // Compression
    // https://github.com/expressjs/compression
    this._compression = require('compression');
    // Async
    this._async = require('async');
    this._sequelize = require('sequelize');
    this._crypto = require('crypto');
    this._validator = require('validator');
    // === External Modules end ===

    // === Main variable start ====
    this._db = {};
    this._user = null;
    this._getUserLogin = function() {
        if (self._user && self._user.login) return self._user.login;
        else return null;
    };
    this._worker = null;
    this._subscribers = []; // {name: name, onExit: function}
    this._handlers = []; // {path: path, method: method, handler: handler, roles: roles,  module: module}
    this._businessLogic = [];
    this.getLogLevel = function() { return self._cfg.logLevel; }
    this._cfg = JSON.parse(self._fs.readFileSync(self._path.resolve(__dirname, 'server.cfg'), 'utf8'));
    
    // === My Modules start ===
    // roleBuilder
    this._rb = new RoleBuilder();

    // Const
    this._myConst = require('./inc/const.js');

    // Common
    this._myCommon = require('./inc/common.js').init(self._myConst, self._cfg.logPath, self._subscribers);

    // AD
    this._myAd = require('./inc/ad.js').init(self._myConst, self._myCommon, self._cfg.adDomain, self._cfg.adController, self._cfg.adAdmin, self._cfg.adPass, self._cfg.adPort, self._subscribers, self.getLogLevel);

    // PS
    this._myPs = require('./inc/ps.js').init(self._myConst, self._myCommon, self._cfg.ps.executionPolicy, self._cfg.ps.debugMsg, self._cfg.ps.noProfile, self._subscribers, self.getLogLevel);

    // Cripographic
    this.enc = function(str) {
        cipher = self._crypto.createCipher('aes192', self.moduleName());
        qqq = cipher.update(str, 'utf8', 'hex');
        qqq += cipher.final('hex'); 
        return qqq;
    };
    this.dec = function(str) {
        decipher = self._crypto.createDecipher('aes192', self.moduleName());
        qqq = decipher.update(str, 'hex', 'utf8');
        qqq += decipher.final('utf8'); 
        return qqq;
    };

    // === My Modules end ===

    this._newRoleBuilder = function() {
        return new RoleBuilder();
    }
    this._startMaster = function() {                
        if (self._myCommon.isInDebug()) { self._myCommon.toLog('Run in debug mode. Throng (Clustering) is not used.'); }

        self._myCommon.toLog(self.moduleName() + '. Started master. Application ' + self.appName() + ' v' + self.ver());
        self._myCommon.toLog(self.moduleName() + "._startMaster: CPUs count is [" + self._os.cpus().length + "]");

        if (self._myCommon.isInDebug() === true) {
            self._makeListener(0);
        }
    };

    // This will be called [CPU count] times
    this._startWorker = function(id) {
        self._myCommon.toLog('Started worker {' + id + '}');

        if (id <= self._os.cpus().length) {
            if (self._myCommon.isInDebug() === false) {
                self._makeListener(id);
            }
        } else { self._myCommon.toLog("[" + id + "] ---Fuck! How it possible?! Good bye.---", "Error") }
    };
    this._mySql = null;

    this._makeListener = function(id) {
        // SQL
        self._mySql = null;
        switch (self._cfg.dbType) {
            case self._myConst.dbType.mssql:
                {
                    // MS SQL
                    self._mySql = new self._sequelize('Tst', 'Administrator', 'P@ssw0rd', {
                        host: 'mssvs01',
                        dialect: 'mssql',                        
                        logging: false, //console.log,
                    });
                    break;
                }
            case self._myConst.dbType.sqlite:
                {
                    // SqLite
                    self._mySql = new self._sequelize({
                        host: 'localhost',
                        dialect: 'sqlite',
                        pool: {
                            max: 5,
                            min: 0,
                            idle: 10000
                        },
                        logging: false, //console.log,
                        // SQLite only
                        storage: self._path.join(__dirname, self._myConst.dbDir + self._cfg.dbFileName)
                    });
                    break;
                }
            default:
                { throw "Please define Database type to work with"; }
        }
        self._mySql.connected = function() { return true; };
        self._dbConnected(null, { id: id });

        // Authentication
        self._myAuth = require('./inc/auth.js').init(self._myConst, self._myCommon, self._myAd, self._mySql, self._db, self._cfg.authType, self._cfg.rolesPrefix, self._subscribers, self.getLogLevel, self.enc, self.dec, self._cfg.adAuthAutoCreate);

        var im = self._app
            .use(self._onAuth)
            .use(self._bodyParser.json({ type: ['text/json', 'application/json'] }))
            .use('*', self._allOfThemAtStart)
            .use(self.removeXPoweredByHeader)
            .listen(self._cfg.port, self._onListen);

        self._worker = { im: im, sql: self._mySql, id: id, ad: self._myAd, auth: self._myAuth, db: self._db };
        self._registerHandler('/$', 'get', self._getCommon, null, self, false, false);
        self._registerHandler('/js/my/*', 'get', self._getCommon, null, self, false, false);
        self._registerHandler('/css/*', 'get', self._getCommon, null, self, false, false);
        self._registerHandler('/js/ext/*', 'get', self._getCommon, null, self, false, false);
        self._registerHandler('/img/*', 'get', self._getCommon, null, self, false, false);
        self._registerHandler('/about', 'get', self._getAbout, null, self, false, false, 'About Server', 'About Server Software', null);
        self._registerHandler('/api', 'get', self._getApi, null, self, false, false, 'API Description', 'Get Server\'s API description and specification', null);
        // ------- Test methods ----------
        self._registerHandler('/mssql', 'get', self._getHmm, null, self, false, true);
        self._registerHandler('/sqlite', 'get', self._getFuck, self._newRoleBuilder().and('Administrator').and('Guest'), self, false, true);
        //self._registerHandler('/ps', 'get', self._getPs, self._newRoleBuilder().and('Administrator').and('Guest'), self, false, true);
        self._registerHandler('/ps', 'get', self._getPs, null, self, false, true);
        self._registerHandler('/add', 'post', self._postSomething, self._newRoleBuilder().and('Administrator').and('Guest'), self, true, true);

        // --- Invoke business logic start ---
        var tmp = self._path.resolve(__dirname, self._cfg.businessLogicDir);
        if (self._myCommon.isFileExists(tmp)) {
            self._fs.readdir(tmp, function(err, files) {
                if (!err) {
                    files.forEach(function(itm, idx, arr) {
                        if (self._path.extname(self._path.resolve(tmp, itm)).toLowerCase() == '.js') {
                            self._myCommon.toLog('Business Logic: Processing [' + itm + ']...');
                            var www = require(self._path.resolve(tmp, itm)).init(
                                id,
                                self._app,
                                self._worker.im,
                                self._myConst,
                                self._myCommon,
                                self._mySql,
                                self._sequelize,
                                self._db,
                                self._myAd,
                                self._myAuth,
                                self._cfg,
                                self._registerHandler,
                                self._unregisterHandler,
                                self._subscribers,
                                self._newRoleBuilder,
                                self.makeStandardResponse,
                                self.getHandlerPathPrefix,
                                self.getLogLevel,
                                self._async,
                                self._getUserLogin,
                                self.enc,
                                self.dec,
                                self._validator
                            );
                            if (www) {
                                self._businessLogic.push(www);
                            } else { self._myCommon.toLog('Error loading [' + itm + '] Module.', 'error'); }
                            self._myCommon.toLog('Business Logic: [' + www.moduleName() + ' v' + www.ver() + '] Initialized.');
                        }
                    });

                } else { self._myCommon.toLog('Error finding Business Logic files in the directory [' + tmp + '] defined in Config', 'error'); }
            });
        }
        // --- Invoke business logic end  ---        
        // self._prepareAllRegisteredHandlers();
    };

    this.prepareOneRegisteredHandler = function(itm) {
        switch (itm.method) {
            case 'get':
                {
                    self._app.get(itm.path, self._myGlobalHandler);
                    break;
                }
            case 'post':
                {
                    self._app.post(itm.path, self._myGlobalHandler);
                    break;
                }
            case 'put':
                {
                    self._app.put(itm.path, self._myGlobalHandler);
                    break;
                }
            case 'delete':
                {
                    self._app.delete(itm.path, self._myGlobalHandler);
                    break;
                }
            case 'set':
                {
                    self._app.set(itm.path, self._myGlobalHandler);
                    break;
                }
        }
    };

    this._prepareAllRegisteredHandlers = function() {
        // ------------- Global handlers start ----------------
        self._handlers.forEach(function(itm, idx, arr) {
            // handlers: []; //{path: path, method: method, handler: handler, roles: roles,  module: module}
            self.prepareOneRegisteredHandler(itm);
        });
        // ------------- Global handlers end   ----------------
    };

    this.getHandlerPathPrefix = function() {
        return self._cfg.handlerPathPrefix;
    };

    this._registerHandler = function(
        apiPath, method, handler, roleBuilder, ownedByModule, useTransaction, useHandlerPathPrefix, handlerName, handlerDescr, handlerHtmlDescr
    ) {
        // handlers: []; //{path: path, method: method, handler: handler, roles: roles,  module: module}
        var res = false;
        if (ownedByModule.moduleName() != self.moduleName()) { apiPath = self._path.join(ownedByModule.moduleName().toLowerCase(), apiPath) }
        // roleBuilder will not checked becuase it can be null
        if (
            apiPath &&
            typeof apiPath == 'string' &&
            typeof method == 'string' &&
            self._httpMethod.lowercase.indexOf(method.toLowerCase()) > -1 &&
            handler &&
            typeof handler == 'function' &&
            typeof ownedByModule == 'object'
        ) {
            if (useHandlerPathPrefix && self._cfg.handlerPathPrefix.length > 0 && !apiPath.startsWith(self._cfg.handlerPathPrefix))
                apiPath = self._path.join(self.getHandlerPathPrefix(), apiPath).split('\\').join('/');
            self._handlers.push({
                path: apiPath,
                method: method.toLowerCase(),
                handler: handler,
                roleBuilder: roleBuilder,
                module: ownedByModule,
                name: handlerName,
                descr: handlerDescr,
                htmlDescr: handlerHtmlDescr
            });
            // Without authorization ?
            if (!roleBuilder) { self._cfg.pathsWithoutAuth.push(apiPath); }
            // Use Transaction ?
            if (useTransaction) { self._cfg.transactionUriMasks.push({ path: apiPath, method: method }); }
            // Register this one
            self.prepareOneRegisteredHandler(self._handlers[self._handlers.length - 1]);
            res = true;
        }
        return res;
    };

    this._unregisterHandler = function(path, thisModule, useHandlerPathPrefix) {
        if (useHandlerPathPrefix && self._cfg.handlerPathPrefix.length > 0 && !path.startsWith(self._cfg.handlerPathPrefix))
            path = self._path.join(self.getHandlerPathPrefix(), path).split('\\').join('/');
        if (thisModule) {
            var data = new self._jinq().from(self._handlers).delete().at(function(col, index) { return col[index].path == path && col[index].module == thisModule; }).select();
            self._handlers = data;
        } else {
            var data = new self._jinq().from(self._cfg.pathsWithoutAuth).delete().at(function(col, index) { return col[index] == path; }).select();
            self._cfg.pathsWithoutAuth = data;
        }
    };

    this._onListen = function() {
        self._myCommon.toLog('Server is running on port [' + self._cfg.port + '] id={' + self._worker.id + '}');
    };

    this.removeXPoweredByHeader = function(req, res, next) {
        if (!self._myCommon.isInDebug())
            res.removeHeader("X-Powered-By");
        next();
    };

    // Authentication
    this._onAuth = function(req, res, next) {
        self._user = self._auth(req);        
        if (self._user) {
            self._user.login = self._user.name;
            self._user.name = null;
            if (self.getLogLevel() == 3) self._myCommon.toLog('User [' + self._user.login + ']. trying to authenticate...');
            self._worker.auth.authorize(self._user.login, self._user.pass, self._onAuthCallback, { next: next, req: req, res: res, userLogin: self._user.login });
        } else {
            self._onAuthCallback(self._worker.auth.getAuthorizationTemplate(), { next: next, req: req, res: res, userLogin: null });
        }
    };

    this._onAuthCallback = function(userWithRoles, param) {
        if (!userWithRoles.login || userWithRoles.roles.length == 0) {
            if (param.req.method == 'GET' && self._myCommon.isPathMatchToOneFromArray(param.req.originalUrl, self._cfg.pathsWithoutAuth)) {
                // Unauthorized access to the any paths using 'GET'. It is normally
                if (self.getLogLevel() == 3) self._myCommon.toLog('Unauthorized request to the one of allowed paths. Don\'t worry.');
                self._user = userWithRoles;
                param.next();
            } else {
                // Unauthorized access not to the root or not using 'GET' to the root. Prohibited
                self._myCommon.toLog(self._myConst.msgUnauthorized);
                param.res.status(self._httpStatus.UNAUTHORIZED).end(self._httpStatus.getStatusText(self._httpStatus.UNAUTHORIZED));
            }
        } else {
            if (self.getLogLevel() == 3) self._myCommon.toLog('onAuthCallback: Authenticated. Going to the next handler.');
            self._user = userWithRoles;
            param.next();
        }
    };

    this._sendFileIfExists = function(req, res, uri) {
        var fName = self._path.join(__dirname, self._myConst.siteBase + uri);
        fName = self._path.normalize(fName);
        try {
            if (self._myCommon.isFileExists(fName)) {
                res.sendFile(fName);
            } else throw 'File [' + fName + '] does not exist';
        } catch (err) {
            res.statusCode = self._httpStatus.NOT_FOUND;
            if (self._myCommon.isInDebug()) {
                res.end(self._httpStatus.getStatusText(res.statusCode) + '. ' + err);
            } else {
                res.end(self._httpStatus.getStatusText(res.statusCode) + '. Root file not found. Please contact the Site Administrator for details.');
            }
        }
    };


    // ========================= Transactions support start ==============================
    this._allOfThemAtStart = function(req, res, next) {
        var data = new self._jinq().from(self._cfg.transactionUriMasks).where(function(row, idx) { return (row.path.toLowerCase() == req.baseUrl.toLowerCase() && row.method.toLowerCase() == req.method.toLowerCase()); }).select();
        if (data && data.length > 0) {
            try {
                self._worker.sql.transaction('start');
                //param.res.on('error', self._allOfThemAfterError);
                setTimeout(self.waitForTransactionStarted, self._cfg.checkForTransactionStartedEach, { req: req, res: res, next: next, msInWaitState: 0 });
            } catch (err) {
                res.status(self._httpStatus.INTERNAL_SERVER_ERROR).send(self.makeStandardResponse(self._httpStatus.INTERNAL_SERVER_ERROR, err));
            }
        } else {
            // There is no Transaction needs
            next();
        }
    };

    this.waitForTransactionStarted = function(param) {
        if (self._mySql.isTransactionInProgress()) {
            param.res.on('finish', self._allOfThemAfterFinish);
            param.next();
        } else {
            if (param.msInWaitState < self._cfg.checkForTransactionStartedTimeout * 1000) {
                param.msInWaitState += self._cfg.checkForTransactionStartedEach;
                setTimeout(self.waitForTransactionStarted, self._cfg.checkForTransactionStartedEach, param);
            } else {
                self._worker.sql.needRollback(true);
                self._worker.sql.transaction('rollback');
                param.res.status(self._httpStatus.INTERNAL_SERVER_ERROR).send(self.makeStandardResponse(self._httpStatus.INTERNAL_SERVER_ERROR, null));
            }
        }
    };

    this._allOfThemAfterFinish = function() {
        setTimeout(self._worker.sql.transaction, self._cfg.transactionFinishDelay, 'finish');
    };

    this._handlerStartedCallback = function(param) {
        //
    };

    this._handlerFinishedCallback = function(param) {
        //
    };

    /*
    this._allOfThemAfterError = function(err) {
        if (err) {
            self._myCommon.toLog(JSON.stringify(err));
        }
    };
    */
    // ========================= Transactions support end   ==============================

    // =============================== Files without authorization start ====================================    
    this._getCommon = function(req, res, next) {
        if (req.originalUrl === '/') self._sendFileIfExists(req, res, self._myConst.rootHtml);
        else self._sendFileIfExists(req, res, req.originalUrl);
    };
    // =============================== Files without authorization end  =====================================

    // ============================= Get API and About start ===============================
    this._getApi = function(req, res, next) {
        var mod = new self._jinq().from(self._handlers).where(function(row, index) { return row.name !== undefined && row.name !== null; }).select();
        var m = [];
        if (mod && mod.length > 0) {
            mod.forEach(function(itm, idx, arr) {
                m.push({ name: itm.name, descr: itm.descr, htmlDescr: itm.htmlDescr, apiPath: itm.path, method: itm.method, module: itm.module.moduleName() });
            });
        }
        res.status(self._httpStatus.OK).send(self.makeStandardResponse(self._httpStatus.OK, {
            apiPrefix: self.getHandlerPathPrefix(),
            api: m
        }));
    };

    this._getAbout = function(req, res, next) {
        res.status(self._httpStatus.OK).send(self.makeStandardResponse(self._httpStatus.OK, {
            moduleName: self.moduleName(),
            appName: self.appName(),
            ver: self.ver(),
            descr: self.txtDescr(),
            htmlDescr: self.htmlDescr()
        }));
    };
    // ============================= Get API and About and   ===============================


    // -------------- GLOBAL HANDLER start ---------------------
    this._myGlobalHandler = function(req, res, next) {
        // handlers: []; //{path: path, method: method, handler: handler, rolesBuilder: rolesBuilder,  module: module}
        if (self._handlers && self._handlers.length > 0) {

            var data = new self._jinq().from(self._handlers).where(function(row, index) { return row.method === req.method.toLowerCase() && row.path === req.route.path; }).select();
            if (data && data.length > 0) {
                data.forEach(function(itm, idx, arr) {
                    try {
                        if (!itm.roleBuilder || itm.roleBuilder.isThisOk(self._user.roles)) {
                            // Roles are OK
                            if (itm.handler(req, res)) {
                                // next();
                            }
                        } else { res.status(self._httpStatus.UNAUTHORIZED).send(self.makeStandardResponse(self._httpStatus.UNAUTHORIZED, null)); }
                    } catch (err) {
                        self._myCommon.toLog('GLOBAL: [' + req.method.toUpperCase() + '] Module: [' + itm.module.moduleName() + '] Error: [' + err + ']', 'error');
                        // next();
                    }
                });
            } else { res.status(self._httpStatus.NOT_FOUND).send(self.makeStandardResponse(self._httpStatus.NOT_FOUND, null)); }
        } else { res.status(self._httpStatus.NOT_IMPLEMENTED).send(self.makeStandardResponse(self._httpStatus.NOT_IMPLEMENTED, null)); }
    };
    // -------------- GLOBAL HANDLER end   ---------------------

    this.makeStandardResponse = function(httpStatusCode, data) {
        try {
            return { date: self._myCommon.getDateTime(), httpStatusCode: httpStatusCode, httpStatusMessage: self._httpStatus.getStatusText(httpStatusCode), data: data };
        } catch (err) {
            return { date: self._myCommon.getDateTime(), httpStatusCode: self._httpStatus.INTERNAL_SERVER_ERROR, httpStatusMessage: err, data: null };
        }
    };










    // -------------- get '/mssql' start ----------------------------
    this._getHmm = function(req, res, next) {
        if (self._worker.sql.connected()) {
            //app.emit(myConst.eventHandlerStarted, { req: req, res: res, next: next });
            self._worker.sql.query('select * from Usr', self._queryCompleted, { res: res });
            self._myCommon.toLog('getRoot: Data sent. id=[' + self._worker.id + ']');
            //app.emit(myConst.eventHandlerFinished, { req: req, res: res, next: next });
            return false;
        }
    };
    // -------------- get '/mssql' start ----------------------------

    // -------------- get '/sqlite' start ------------------------
    this._getFuck = function(req, res, next) {
        if (self._worker.sql.connected()) {
            self._worker.sql.query('select * from Rol', self._queryCompleted, { res: res });
            return false;
        }
    };
    // -------------- get '/sqlite' end  ------------------------

    // -------------- get '/ps' start -------------------------
    this._psDone = function(param) {
        param.res.status(self._httpStatus.OK).send(
            self.makeStandardResponse(self._httpStatus.OK, param.result)
        );
    };

    this._getPs = function(req, res, next) {
        if (self._worker.sql.connected()) {
            var psScript = self._fs.readFileSync(self._path.resolve(__dirname, '1.ps1'), 'utf8');
            self._myPs.run(psScript, self._psDone, { req: req, res: res, next: next, });
        }
    };
    // -------------- get '/ps' end  -------------------------

    // -------------- post '/add' start ---------------------------
    this._postSomething = function(req, res, next) {
        setTimeout(self._worker.sql.modify, 300, "insert into Rol(Name, Descr) values('Administrator1', 'sdasdads')", self._modifyCompleted, { res: res });
        return false;
    };
    // -------------- post '/add' end  ---------------------------








    // ------------- database Callbacks start -------------------
    this._dbConnected = function(err, param) {
        if (!err) {
            self._myCommon.toLog('DB Connected. {Worker id = ' + param.id + '}');

            // Common (Login and Log supports)
            self._db.Usr = self._mySql.define('Usr', {
                Id: { type: self._sequelize.BIGINT, primaryKey: true, autoIncrement: true },
                Login: { type: self._sequelize.STRING(50), allowNull: false },
                Pass: { type: self._sequelize.STRING(50), allowNull: false },
                Name: { type: self._sequelize.STRING(50), allowNull: false },
                IsLocked: { type: self._sequelize.BOOLEAN, allowNull: false },
            }, { freezeTableName: true, timestamps: false });
            self._db.Rol = self._mySql.define('Rol', {
                Id: { type: self._sequelize.BIGINT, primaryKey: true, autoIncrement: true },
                Name: { type: self._sequelize.STRING(50), allowNull: false },
                Descr: { type: self._sequelize.STRING(100), allowNull: true },
            }, { freezeTableName: true, timestamps: false });
            self._db.Module = self._mySql.define('Module', {
                Id: { type: self._sequelize.BIGINT, primaryKey: true, autoIncrement: true },
                Name: { type: self._sequelize.STRING(50), allowNull: false },
                Descr: { type: self._sequelize.STRING(100), allowNull: true },
            }, { freezeTableName: true, timestamps: false });
            self._db.UsrRol = self._mySql.define('UsrRol', {
                Id: { type: self._sequelize.BIGINT, primaryKey: true, autoIncrement: true },
                Usr: { type: self._sequelize.BIGINT, allowNull: false, references: { model: self._db.Usr, key: 'Id' } },
                Rol: { type: self._sequelize.BIGINT, allowNull: false, references: { model: self._db.Rol, key: 'Id' } },
            }, { freezeTableName: true, timestamps: false });
            self._db.Log = self._mySql.define('Log', {
                Id: { type: self._sequelize.BIGINT, primaryKey: true, autoIncrement: true },
                Dat: { type: self._sequelize.DATE, allowNull: false },
                Uri: { type: self._sequelize.STRING(124), allowNull: true },
                Data: { type: self._sequelize.STRING(4096), allowNull: true },
            }, { freezeTableName: true, timestamps: false });

            self._db.Usr.belongsToMany(self._db.Rol, { through: 'UsrRol', foreignKey: 'Usr' });
            self._db.Rol.belongsToMany(self._db.Usr, { through: 'UsrRol', foreignKey: 'Rol' });

            self._db.Log.belongsToMany(self._db.Usr, { through: 'LogUsr', foreignKey: 'Usr' });
            self._db.Log.belongsToMany(self._db.Module, { through: 'LogModule', foreignKey: 'Module' });

        } else {
            self._myCommon.toLog('DB Connection error.' + result.state + ' Error: [' + result.err + '] {Worker id = ' + param.id + '}');
        }
    };

    this._queryCompleted = function(result, param) {
        param.res.status(self._httpStatus.OK).send(
            self.makeStandardResponse(self._httpStatus.OK, result)
        );
        self._myCommon.toLog('queryCompleted: Data sent. id=[' + self._worker.id + ']');
    };

    this._modifyCompleted = function(err, param) {
        if (err) {
            if (self._myCommon.isInDebug()) {
                if (err.message) { err.msg = err.message; }
                if (err.stack) { err.stackCall = err.stack; }
            }
            if (self._myCommon.isInDebug()) {
                param.res.status(self._httpStatus.CONFLICT).send(
                    self.makeStandardResponse(self._httpStatus.CONFLICT, { error: err })
                )
            } else {
                param.res.status(self._httpStatus.CONFLICT).send(
                    self.makeStandardResponse(self._httpStatus.CONFLICT, { error: self._httpStatus.getStatusText(ret) })
                );
            }
        } else {
            param.res.status(self._httpStatus.CREATED).send(
                self.makeStandardResponse(self._httpStatus.CREATED, undefined)
            );
        }
    };
    // ------------- database Callbacks end  -------------------



    // ------------- Cleanup --------------
    process.on('exit', function() {
        if (self._subscribers && self._subscribers.length > 0) {
            for (i = self._subscribers.length - 1; i >= 0; i--) {
                self._myCommon.toLog('Finalizing [' + self._subscribers[i].name + ']...');
                try {
                    self._subscribers[i].onExit();
                } catch (err) { self._myCommon.toLog(err.message, err.name, err.stack); }
            }
        }
    });
}


// ================= Role builder ==========================
function RoleBuilder() {
    var self = this;

    // https://jinqjs.readme.io/docs/what-is-jinqjs
    this._jinq = require('jinq');

    this._and = [];
    this._not = [];


    this.and = function(name) {
        if (typeof name == 'string') {
            self._and.push(name.toLowerCase());
        }
        return self;
    };
    this.not = function(name) {
        if (typeof name == 'string') {
            self._not.push(name.toLowerCase());
        }
        return self;
    };
    this.get = function() {
        return { and: self._and, not: self._not };
    };
    this.isEmpty = function() {
        if (self._and.length === 0 && self._not.length === 0) return true;
        else return false;
    };
    this.isThisOk = function(roles) {
        var ret = false;

        if (self.isEmpty()) ret = true;
        else if (roles instanceof Array) {
            // Roles are Objects ?
            if (roles.length > 0) {
                if (typeof roles[0] == 'object') {
                    var tmp = [];
                    roles.forEach(function(itm, idx, arr) { tmp.push(itm.name.toLowerCase()); });
                    roles = tmp;
                }
            }

            for (i = 0; i < roles.length; i++) { if (typeof roles[i] == 'string') roles[i] = roles[i].toLowerCase(); }
            // Not
            var data = new self._jinq().from(self._not).in(roles).select();
            if (data && data.length === 0) {
                // And
                data = new self._jinq().from(roles).in(self._and).select();
                if (data && data.length === self._and.length) {
                    ret = true;
                }
            }
        }

        return ret;
    };
}

var main = new Main().start();