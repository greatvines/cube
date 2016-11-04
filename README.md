# Cube

**Cube** is a system for collecting timestamped events and deriving metrics. By collecting events rather than metrics, Cube lets you compute aggregate statistics *post hoc*. It also enables richer analysis, such as quantiles and histograms of arbitrary event sets. Cube is built on [MongoDB](http://www.mongodb.org) and available under the [Apache License](/square/cube/blob/master/LICENSE).

Want to learn more? [See the wiki.](https://github.com/square/cube/wiki)

## Docker

This branch supports building cube into a docker container. The dependencies are included as parts of them are not available in npm repositories anymore. This allows to create a container with the command:

`docker build -t cube .`

The image can be configured by changing the default values of those environment variables:

```bash
MONGODB_URI=mongodb://localhost:27017/cube_development
PORT=1080
EVALUATOR_AUTHENTICATOR=allow_all
COLLECTOR_AUTHENTICATOR=allow_all
```

Finally the container can be started for example with:

`docker run -p 1080:1080 -e MONGODB_URI=mongodb://mongodb:27017/cube cube bin/collector`
