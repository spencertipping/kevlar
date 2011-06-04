// Kevlar web framework | Spencer Tipping
// Licensed under the terms of the MIT source code license

// Introduction.
// I'm writing kevlar because I want a very simple, reliable way to deploy applications. There are two ideas here. First, a web application is a single HTML page that talks to REST APIs. Second,
// some kind of failure is inevitable, so requests and replies should all be logged in a replayable format to minimize data loss.

// Interface.
// There are exactly two kinds of endpoints. One is the default URL /, which maps to a precompiled HTML page with no external references. The other is an RPC with a URL of the form /foo, where
// 'foo' represents the name of the function being called. (It can contain arbitrary characters.) All RPC functions follow a JSON-based protocol and have logging and diagnostics built in.

// By default, logging happens to the filesystem in date-stamped files that rotate each hour. This can be changed by providing a different LogStream object -- this is like a WriteStream but
// simpler. All you have to do is provide three methods: request(), reply(), and error(). The parameters that are given to each of these methods are described below.

// Any errors generated by the server are sent as connection IDs to the client. For example, suppose you request '/foo' with invalid JSON. You'll get a reply like this:

// | HTTP 400 Bad Request
//   Content-Type: text/plain
//   Content-Length: ...
//   ...
//   2011.0601.1242.10092181               // <- This is a connection ID

// Each connection has a unique connection ID that can later be used to identify it in the logs. Kevlar provides utilities to search the logs for connections in log files.

//   Request parameters.
//   Each log entry describes a complete event that happened. Here are the possibilities for request entries:

//   | 1. Valid RPC: If the URL matches an RPC endpoint and the data was parseable as JSON, then wait for all of the POST data and return this object:
//                                                                 {id, url, headers, json, date}.
//     2. Invalid RPC because the data can't be parsed:            {invalid: 'json', url, headers, data, date}.
//     3. Invalid RPC because the data is too large:               {invalid: 'size', url, headers, data, date}.
//     4. Invalid RPC because the method or URL are wrong:         {invalid: 'method', url, method, headers, date}.
//     5. Valid page request:                                      {page: true, id, url, headers, date}.

//   In cases 2-4, the server replies 400, 413, and 405, respectively. All valid replies are 200.

//   Reply parameters.
//   The reply() callback is invoked when an RPC endpoint replied to the request successfully. Here are the possibilities:

//   | 1. Valid RPC reply: {id, url, json, date, latency}          - In this case, the server replies 200 with content-type application/json
//     2. Valid page reply: {id, url, date, latency}               - In this case, the server replies 200 with content-type text/html

//   Error parameters.
//   The error() callback is invoked when an RPC endpoint is reached but throws an error for some reason or fails to reply before the reply timeout (5 minutes by default). Here are the
//   possibilities:

//   | 1. Timeout: {id, url, date, latency}                        - In this case the server sends a 503 (service unavailable)
//     2. RPC function error: {id, url, error, date, latency}      - In this case the server sends a 500 (internal server error)
//     3. Toplevel server error: {error, date}                     - No server reply, since we don't know what caused the error

//   Either of these conditions causes a message to be printed to stderr, since they are both abnormal and avoidable.

// Creating the HTML page.
// The server just looks for a file called 'index.html' in the current directory. If this file exists, it is served for each request to /. Otherwise requesting / returns 404.

// Writing an RPC endpoint.
// RPC endpoints are just functions that transparently have their arguments JSON-decoded and have their return values JSON-encoded. They are also generally written in CPS. For example, here's how
// you might write a 'hello world' application:

// | var kevlar = require('./kevlar');
//   var server = kevlar.server({sayhi: function (name) {
//     this('hello ' + name);
//   }});
//   require('http').createServer(server).listen(8080);

// Calling this function using a server-side HTTP client or using the client-side wrapper is straightforward:

// | var rpc = kevlar.rpc('sayhi');
//   rpc('bob', function (reply) {
//     console.log('the server said ' + reply);
//   });

// You can also use regular AJAX from the browser:

// | $.ajaxSetup({contentType: 'application/json'});
//   $.post('/sayhi', JSON.stringify(['bob']), function (reply_array) {
//     alert('the server said ' + reply_array[0]);
//   });

  caterwaul.js_all()(function (exports) {
    // Immutable configuration variables
    const reply_timeout_interval  = 300000,
          request_body_size_limit = 1000000;

    // Helper functions
    const next_server_id    = ++id -given.nothing -where [id = 0],
          filesystem_logger = {request: logger_for('request'), reply: logger_for('reply'), error: logger_for('error')}
                              -where [TODO];

    exports.server(endpoints, options) = handle_request

      -where [requests                      = {},
              responses                     = {},
              timeouts                      = {},
              times                         = {},

              default_options               = {log: filesystem_logger},
              settings                      = caterwaul.merge(default_options, options),

              valid_rpcs                    = endpoints /pairs *[['/#{x[0]}', x[1]]] |object |seq,

              intent_is_rpc(r)              = r.method === 'POST',
              rpc_endpoint_for(url)         = url.charAt(0) === '/' && valid_rpcs[url],

              handle_request(req, res)      = handle_tracked(track(req, res)),
              handle_tracked(id)            = intent_is_rpc(requests[id]) ? handle_rpc(id) : handle_page(id),
              handle_rpc(id)                = endpoint ? handle_rpc_data(id, endpoint) : invalid_method_error(id),
              handle_page(id)               = valid_page_request(id) -then- valid_page_reply(id),

              handle_rpc_data(id, f)        = collect_chunks(id, given.data in parse_and_invoke(id, data, f)),

              parse_and_invoke(id, d, f)    = f.call(reply_with_arguments, json)
                                              -when.json
                                              -where  [reply_with_arguments() = valid_rpc_reply(id, Array.prototype.slice.call(arguments)),
                                                       json                   = JSON.parse(d) -safely- invalid_parse_error(id, d) /re [false]]
                                              -safely [rpc_error(id, e)],

              collect_chunks(id, cc)        = requests[id] -effect [it.on('data', given.c [size_ok(c) ? chunks.push(c) : too_big()]), it.on('end', cc(chunks.join('')))]
                                                            -where [chunks      = [],
                                                                    size_so_far = 0,
                                                                    too_big()   = invalid_size_error(id, size_so_far) -effect [chunks = null, too_big() = null],
                                                                    size_ok(s)  = (size_so_far += s.length) < request_body_size_limit],

              server_id                     = next_server_id(),
              next_sequence_number          = given.nothing [++n >= 1000000 ? (n = 100000) : n] -where [n = 100000],
              request_id()                  = '#{d.getYear()}.#{n(d.getMonth() + 1)}#{n(d.getDate())}.#{n(d.getHours())}#{n(d.getMinutes())}.#{server_id}.#{next_sequence_number()}'
                                              -where [d = new Date(), n(x) = x < 10 ? '0#{x}' : x],

              track(req, res)               = id -effect [requests[id]  = req,
                                                          responses[id] = res,
                                                          times[id]     = +new Date(),
                                                          timeouts[id]  = setTimeout(timeout_error(id), reply_timeout_interval)] -where [id = request_id()],

              clear(id)                     = delete requests[id] -then- delete responses[id] -then- delete timeouts[id] -then- delete times[id],

              reply_with_error(id, code)    = responses[id] -se [it.writeHead(code, {'content-type': 'text/plain'}), it.end(id)]                                          -then- clear(id),
              reply_with_json(id, json)     = responses[id] -se [it.writeHead(200, {'content-type': 'application/json'}), it.end(JSON.stringify(json))]                   -then- clear(id),
              reply_with_page(id)           = responses[id] -se [it.writeHead(200, {'content-type': 'text/html'}), require('fs').createReadStream('index.html').pipe(it)] -then- clear(id),

              request_log_base(id)          = {id: id, url: r.url, headers: r.headers, date: times[id]}                 -where [r = requests[id]],
              reply_log_base(id)            = {id: id, url: r.url, date: +new Date(), latency: +new Date() - times[id]} -where [r = requests[id]],

              log_request_error(id, stuff)  = settings.log.request(caterwaul.merge(request_log_base(id), stuff)),
              log_request(id, stuff)        = settings.log.request(caterwaul.merge(request_log_base(id), stuff)),
              log_reply_error(id, stuff)    = settings.log.error  (caterwaul.merge(reply_log_base  (id), stuff)),
              log_reply(id, stuff)          = settings.log.reply  (caterwaul.merge(reply_log_base  (id), stuff)),

              valid_rpc_reply(id)(json)     = log_reply(id, {json: json}) -then- reply_with_json(id, json),
              valid_page_reply(id)          = log_reply(id, {})           -then- reply_with_page(id),

              timeout_error(id)()           = log_reply_error(id, {})         -then- reply_with_error(id, 503),
              rpc_error(id, e)              = log_reply_error(id, {error: e}) -then- reply_with_error(id, 500),

              valid_rpc_request(id, json)   = log_request(id, {json: json}),
              valid_page_request(id)        = log_request(id, {page: true}),

              invalid_method_error(id)      = log_request_error(id, {invalid: 'method', method: requests[id].method}) -then- reply_with_error(id, 405),
              invalid_size_error(id, size)  = log_request_error(id, {invalid: 'size',   size:   size})                -then- reply_with_error(id, 413),
              invalid_parse_error(id, data) = log_request_error(id, {invalid: 'json',   data:   data})                -then- reply_with_error(id, 400)]})(exports);
// Generated by SDoc 
