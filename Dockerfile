FROM ubuntu:trusty

ENV MONGODB_URI=mongodb://localhost:27017/cube_development \
    PORT=1080 \
    EVALUATOR_AUTHENTICATOR=allow_all \
    COLLECTOR_AUTHENTICATOR=allow_all

RUN apt-get update && apt-get -qq -y install \
  python \
  python-bcrypt \
  npm \
  nodejs \
  nodejs-legacy \
  > /dev/null \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ADD     ./    /app

RUN npm install && npm update

ENTRYPOINT ["node"]
