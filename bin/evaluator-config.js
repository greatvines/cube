// Default configuration for development.
var mongo_url = process.env.MONGODB_URI;
var params = /mongodb:\/\/(?:(\w+):(\w+)@)?([\w\.]+)(?::(\d+))?\/(\w+)/.exec(mongo_url);

module.exports = {
  "mongo-username": params[1],
  "mongo-password": params[2],
  "mongo-host": params[3],
  "mongo-port": parseInt(params[4]),
  "mongo-database": params[5],
  "http-port": process.env.PORT,
  "authenticator": process.env.EVALUATOR_AUTHENTICATOR,
  "valid-email": process.env.VALID_EMAIL_DOMAIN,
  "consumer-secret": process.env.CONSUMER_SECRET
};
