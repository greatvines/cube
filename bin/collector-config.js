module.exports = {
  "mongo-url": process.env.MONGODB_URI,
  "http-port": process.env.PORT,
  "authenticator": process.env.COLLECTOR_AUTHENTICATOR,
  "consumer-secret": process.env.CONSUMER_SECRET
};
