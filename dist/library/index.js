'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.uuid = exports.jwt = exports.Session = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _class, _temp, _initialiseProps;

var _uuid = require('uuid');

var _uuid2 = _interopRequireDefault(_uuid);

var _jsonwebtoken = require('jsonwebtoken');

var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var privateData = new WeakMap();

var Session = exports.Session = function Session(info, token) {
  _classCallCheck(this, Session);

  this.info = info;
  this.token = token;
};

;

exports.jwt = _jsonwebtoken2.default;
exports.uuid = _uuid2.default;
var JwtSessionHelper = (_temp = _class = function JwtSessionHelper(secret) {
  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  _classCallCheck(this, JwtSessionHelper);

  _initialiseProps.call(this);

  if (!secret) {
    throw Error('No "secret" provided');
  }

  privateData.set(this, {
    signSecret: secret.private || secret,
    verifySecret: secret.public || secret
  });

  this.options = {};

  this.options.parsePayload = options.parsePayload || function (payload) {
    return payload;
  };
  this.options.exposeInfo = options.exposeInfo || function (originalData, payload) {
    return {};
  };

  this.options.defaults = _extends({}, options.defaults);

  this.options.signDefaults = _extends({}, this.options.defaults, options.signDefaults);

  this.options.decodeDefaults = _extends({}, this.options.defaults, options.decodeDefaults, options);

  this.options.verifyDefaults = _extends({}, this.options.defaults, options.verifyDefaults, options);

  this.Session = Session;
}, _initialiseProps = function _initialiseProps() {
  var _this = this;

  this.decode = function (token, options) {
    return _jsonwebtoken2.default.decode(token, _extends({}, _this.options.decodeDefaults, options));
  };

  this.verify = function (token, options) {
    var _privateData$get = privateData.get(_this),
        verifySecret = _privateData$get.verifySecret;

    return _jsonwebtoken2.default.verify(token, verifySecret, _extends({}, _this.options.verifyDefaults, options));
  };

  this.sign = function (payload, _options) {
    for (var _len = arguments.length, args = Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) {
      args[_key - 2] = arguments[_key];
    }

    var _privateData$get2 = privateData.get(_this),
        signSecret = _privateData$get2.signSecret;

    var options = _extends({}, _this.options.signDefaults, {
      jwtid: _uuid2.default.v4()
    }, options);
    return _jsonwebtoken2.default.sign.apply(_jsonwebtoken2.default, [payload, signSecret, options].concat(args));
  };

  this.createSession = function (originalData, options) {
    for (var _len2 = arguments.length, args = Array(_len2 > 2 ? _len2 - 2 : 0), _key2 = 2; _key2 < _len2; _key2++) {
      args[_key2 - 2] = arguments[_key2];
    }

    var payload = _this.options.parsePayload(originalData);
    var info = _this.options.exposeInfo(originalData, payload);
    info.token = _this.sign.apply(_this, [payload, options].concat(args));
    return new _this.Session(info, info.token);
  };
}, _temp);
exports.default = JwtSessionHelper;