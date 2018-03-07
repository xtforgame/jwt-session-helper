import uuid from 'uuid';
import jwt from 'jsonwebtoken';

const privateData = new WeakMap();

export class Session {
  constructor(info, token) {
    this.info = info;
    this.token = token;
  }
};

export {
  jwt,
  uuid,
};

export default class JwtSessionHelper {
  constructor(secret, options = {}){
    if(!secret){
      throw Error('No "secret" provided');
    }

    privateData.set(this, {
      secret,
    });

    this.options = {};

    this.options.parsePayload = options.parsePayload || (payload => payload);
    this.options.exposeInfo = options.exposeInfo || ((originalData, payload) => ({}));

    this.options.defaults = {
      ...options.defaults,
    };

    this.options.signDefaults = {
      ...this.options.defaults,
      ...options.signDefaults,
    };

    this.options.decodeDefaults = {
      ...this.options.defaults,
      ...options.decodeDefaults,
      ...options,
    };

    this.options.verifyDefaults = {
      ...this.options.defaults,
      ...options.verifyDefaults,
      ...options,
    };

    this.Session = Session;
  }

  decode = (token, options) => {
    return jwt.decode(token, {
      ...this.options.decodeDefaults,
      ...options,
    });
  };

  verify = (token, options) => {
    let { secret } = privateData.get(this);
    return jwt.verify(token, secret, {
      ...this.options.verifyDefaults,
      ...options,
    });
  };

  sign = (payload, _options, ...args) => {
    const { secret } = privateData.get(this);
    const options = {
      ...this.options.signDefaults,
      jwtid: uuid.v4(),
      ...options,
    };
    return jwt.sign(payload, secret, options, ...args);
  };

  createSession = (originalData, options, ...args) => {
    const payload = this.options.parsePayload(originalData);
    let info = this.options.exposeInfo(originalData, payload);
    info.token = this.sign(payload, options, ...args);
    return new this.Session(info, info.token);
  };
}
