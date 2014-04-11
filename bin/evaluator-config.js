module.exports = {
  "mongo-url": process.env.MONGODB_URI,
  "http-port": process.env.PORT,
  "authenticator": process.env.EVALUATOR_AUTHENTICATOR,
  "valid-email": process.env.VALID_EMAIL_DOMAIN,
  "consumer-secret": process.env.CONSUMER_SECRET
};
