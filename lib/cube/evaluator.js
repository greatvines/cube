var endpoint = require("./endpoint"),
    url = require("url");

// To avoid running out of memory, the GET endpoints have a maximum number of
// values they can return. If the limit is exceeded, only the most recent
// results are returned.
var limitMax = 1e4;

//
var headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Max-Age": "3628800",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

exports.register = function(db, endpoints) {
  var event = require("./event").getter(db),
      metric = require("./metric").getter(db),
      types = require("./types").getter(db);

  //
  endpoints.ws.push(
    endpoint("/1.0/event/get", event),
    endpoint("/1.0/metric/get", metric),
    endpoint("/1.0/types/get", types)
  );

  //
  endpoints.http.push(
    endpoint("GET", "/1.0/event", eventGet),
    endpoint("GET", "/1.0/event/get", eventGet),
    endpoint("GET", "/1.0/metric", metricGet),
    endpoint("GET", "/1.0/metric/get", metricGet),
    endpoint("GET", "/1.0/types", typesGet),
    endpoint("GET", "/1.0/types/get", typesGet),
    endpoint("OPTIONS", "/1.0/event", options),
    endpoint("OPTIONS", "/1.0/event/get", options),
    endpoint("OPTIONS", "/1.0/metric", options),
    endpoint("OPTIONS", "/1.0/metric/get", options),
    endpoint("OPTIONS", "/1.0/types", options),
    endpoint("OPTIONS", "/1.0/types/get", options)
  );

  function eventGet(request, response) {
    var signed = request.signed;
    request = url.parse(request.url, true).query;

    var data = [];

    // Provide default start and stop times for recent events.
    // If the limit is not specified, or too big, use the maximum limit.
    if (!("stop" in request)) request.stop = Date.now();
    if (!("start" in request)) request.start = 0;
    if (!(+request.limit <= limitMax)) request.limit = limitMax;

    if (event(request, callback) < 0) {
      response.writeHead(400, headers);
      response.end(JSON.stringify(data[0]));
    } else {
      response.writeHead(200, headers);
    }

    function callback(d) {
      if (d == null) response.end(JSON.stringify(data.reverse()));
      else data.push(d);
    }
  }

  function metricGet(request, response) {
    var signed = request.signed;
    request = url.parse(request.url, true).query;

    var data = [],
        limit = +request.limit,
        step = +request.step;

    // Provide default start, stop and step times for recent metrics.
    // If the limit is not specified, or too big, use the maximum limit.
    if (!("step" in request)) request.step = step = 1e4;
    if (!("stop" in request)) request.stop = Math.floor(Date.now() / step) * step;
    if (!("start" in request)) request.start = 0;
    if (!(limit <= limitMax)) limit = limitMax;

    // If the time between start and stop is too long, then bring the start time
    // forward so that only the most recent results are returned. This is only
    // approximate in the case of months, but why would you want to return
    // exactly ten thousand months? Don't rely on exact limits!
    var start = new Date(request.start),
        stop = new Date(request.stop);
    if ((stop - start) / step > limit) request.start = new Date(stop - step * limit);
    
    // Add the org ID to the request
    var orgId = signed && signed.context.organization && signed.context.organization.organizationId;
    if (orgId) {
      request.orgId = orgId;
    }

    if (metric(request, callback) < 0) {
      response.writeHead(400, headers);
      response.end(JSON.stringify(data[0]));
    } else {
      response.writeHead(200, headers);
    }

    function callback(d) {
      if (d.time >= stop) response.end(JSON.stringify(data.sort(chronological)));
      else data.push(d);
    }
  }

  function typesGet(request, response) {
    types(url.parse(request.url, true).query, function(data) {
      response.writeHead(200, headers);
      response.end(JSON.stringify(data));
    });
  }
};

function chronological(a, b) {
  return a.time - b.time;
}

function options(request, response) {
	response.writeHead(200, headers);
	response.end();
}
