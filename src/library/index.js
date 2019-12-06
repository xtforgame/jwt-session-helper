import uuid from 'uuid';
import jwt from 'jsonwebtoken';

const privateData = new WeakMap();

export class Session {
  constructor(info, token, payload) {
    this.info = info;
    this.token = token;
    this.payload = payload;
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
      signSecret: secret.private || secret,
      verifySecret: secret.public || secret,
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

    this.issuer = this.options.signDefaults.issuer || 'localhost';
    this.options.signDefaults.issuer = this.issuer;

    this.Session = Session;
  }

  decode = (token, options) => {
    return jwt.decode(token, {
      ...this.options.decodeDefaults,
      ...options,
    });
  };

  verify = (token, options) => {
    let { verifySecret } = privateData.get(this);
    return jwt.verify(token, verifySecret, {
      ...this.options.verifyDefaults,
      ...options,
    });
  };

  sign = (payload, options, ...args) => {
    const { signSecret } = privateData.get(this);
    return jwt.sign(payload, signSecret, {
      ...this.options.signDefaults,
      jwtid: uuid.v4(),
      ...options,
    }, ...args);
  };

  createSession = (originalData, options, ...args) => {
    const payload = this.options.parsePayload(originalData);
    let info = this.options.exposeInfo(originalData, payload);
    info.token = this.sign(payload, options, ...args);
    return new this.Session(info, info.token, payload);
  };
}
