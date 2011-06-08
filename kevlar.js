// Kevlar web stuff | Spencer Tipping
// Licensed under the terms of the MIT source code license

// Introduction.
// Kevlar is a bunch of stuff that may or may not be useful to web application developers. There are two main pieces: the client, comprised of a jQuery-based RPC client, and a bunch of stuff for
// server-end development. The latter piece includes a basic database, a very simple webserver, and some client/server libraries to handle various kinds of encryption and authentication.

kevlar = caterwaul.js_all()(function (require, deglobalize_function) {
  var kevlar = {deglobalize: deglobalize_function};



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

// | var server = kevlar.server({sayhi: function (name) {
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

  (function () {
    // Immutable configuration variables
    const reply_timeout_interval  = 300000,
          request_body_size_limit = 1048576;

    // Helper functions
    const next_server_id = given.nothing in Math.random() * 0xffffffff >>> 0;

    kevlar.server(endpoints, options) = handle_request

    -where [requests                      = {},
            responses                     = {},
            timeouts                      = {},
            times                         = {},

            default_options               = {},
            settings                      = caterwaul.merge(default_options, options) -effect [it.log_database || (it.log_database = kevlar.database('kevlar.server.log'))],

            default_rpcs                  = {'/kevlar/rpc-map': given.nothing in this(endpoints /keys /seq)},
            valid_rpcs                    = caterwaul.merge(default_rpcs, endpoints /pairs *[['/#{x[0]}', x[1]]] |object |seq),

            intent_is_rpc(r)              = r.method === 'POST',
            rpc_endpoint_for(url)         = url.charAt(0) === '/' && valid_rpcs[url],

            handle_request(req, res)      = handle_tracked(track(req, res)),
            handle_tracked(id)            = intent_is_rpc(requests[id]) ? handle_rpc(id, rpc_endpoint_for(requests[id].url)) : handle_page(id),
            handle_rpc(id, endpoint)      = endpoint ? handle_rpc_data(id, endpoint) : invalid_method_error(id),
            handle_page(id)               = valid_page_request(id) -then- valid_page_reply(id),

            handle_rpc_data(id, f)        = collect_chunks(id, given.data in parse_and_invoke(id, data, f)),

            parse_and_invoke(id, d, f)    = valid_rpc_request(id, json) -then- f.apply(reply_with_arguments, json)
                                            -when.json
                                            -where  [reply_with_arguments() = valid_rpc_reply(id, Array.prototype.slice.call(arguments)),
                                                     json                   = JSON.parse(d) -safely- invalid_parse_error(id, d) /re [false]]
                                            -safely [rpc_error(id, e)],

            collect_chunks(id, cc)        = requests[id] -effect [it.on('data', given.c [size_ok(c) ? chunks.push(c) : too_big()]),
                                                                  it.on('end',  given.nothing in cc(chunks && chunks.join('')))]

                                                          -where [chunks      = [],
                                                                  size_so_far = 0,
                                                                  too_big()   = invalid_size_error(id, size_so_far) -effect [chunks = null, too_big() = null],
                                                                  size_ok(s)  = (size_so_far += s.length) < request_body_size_limit],

            server_id                     = next_server_id(),
            next_sequence_number          = given.nothing [++n >= 1000000 ? (n = 100000) : n] -where [n = 100000],
            request_id()                  = '#{d.getFullYear()}.#{n(d.getMonth() + 1)}#{n(d.getDate())}.#{n(d.getHours())}#{n(d.getMinutes())}.#{server_id}.#{next_sequence_number()}'
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

            request_logger                = settings.log_database.hourly_log('request'),
            error_logger                  = settings.log_database.hourly_log('error'),
            reply_logger                  = settings.log_database.hourly_log('reply'),

            log_request_error(id, stuff)  = request_logger(caterwaul.merge(request_log_base(id), stuff)),
            log_request(id, stuff)        = request_logger(caterwaul.merge(request_log_base(id), stuff)),
            log_reply_error(id, stuff)    = error_logger  (caterwaul.merge(reply_log_base  (id), stuff)),
            log_reply(id, stuff)          = reply_logger  (caterwaul.merge(reply_log_base  (id), stuff)),

            valid_rpc_reply(id, json)     = log_reply(id, {json: json}) -then- reply_with_json(id, json),
            valid_page_reply(id)          = log_reply(id, {})           -then- reply_with_page(id),

            timeout_error(id)()           = log_reply_error(id, {})         -then- reply_with_error(id, 503),
            rpc_error(id, e)              = log_reply_error(id, {error: e}) -then- reply_with_error(id, 500),

            valid_rpc_request(id, json)   = log_request(id, {json: json}),
            valid_page_request(id)        = log_request(id, {page: true}),

            invalid_method_error(id)      = log_request_error(id, {invalid: 'method', method: requests[id].method}) -then- reply_with_error(id, 405),
            invalid_size_error(id, size)  = log_request_error(id, {invalid: 'size',   size:   size})                -then- reply_with_error(id, 413),
            invalid_parse_error(id, data) = log_request_error(id, {invalid: 'json',   data:   data})                -then- reply_with_error(id, 400)]})();

// Generated by SDoc 





// Kevlar database component | Spencer Tipping
// Licensed under the terms of the MIT source code license

// Introduction.
// This is a fairly straightforward, bomb-proof database designed for easy use, administration, and disaster recovery. All of the contents are stored directly on the filesystem as JSON text
// files, and all database operations are stored in a replayable log.

// Unlike most databases, kevlar doesn't provide general-purpose tables. Instead, you specify the usage pattern for a collection when you create it. Right now there are two kinds of collections:
// associative hashes and append logs. Associative hashes operate like key-value stores, and append logs operate like text files (though they end up being faster due to record partitioning).

// Using kevlar databases.
// Ease of use is an important prerequisite to having something be bulletproof. Here's how to create and use a database in kevlar:

// | $ node
//   > var k = require('./kevlar');
//   > var test = k.database('test');                              // uses ./test
//   > var foo = test.log('foo');                                  // uses ./test/foo
//   > var bar = test.associative('bar');                          // uses ./test/bar

// Here's the basic idea of using a log:

// | > foo(+new Date() % 3600000, 'hi there');                     // appends 'hi there' to the log and uses the current hour as the partition identifier
//   > foo.find(+new Date() % 3600000, function (result) {         // iterates over all records in a single partition
//       console.log(result);
//     });
//   > foo.find(function (result) {                                // iterates over all records in all partitions
//       console.log(result);
//       return false;                                             // stops iteration
//     });

// And here's what it looks like to use an associative table:

// | > bar('bif', 'baz');                                          // associates 'bar' with 'baz'
//   > bar.find('bif', function (result) {                         // finds the record associated with 'bif'; if it doesn't exist, your callback is invoked on undefined
//       console.log(result);
//     });

// Each of these calls creates any files or directories that don't already exist.

// Indexing stuff.
// Any self-respecting database will provide a way to maintain lists of objects that have some property. Kevlar is self-respecting by this definition, but only barely. It doesn't automatically
// index things; this is up to you. Here's how you build an index (in this example I'm indexing the first letter of each item in the associative table):

// | > var by_letter = test.index('by_letter');                    // create or use an index
//   > by_letter.add('b', 'bar');                                  // adds 'bar' to the collection of things starting with b (this operation is idempotent)
//   > by_letter.find('b', function (result) {                     // retrieves everything that starts with b
//       console.log(result);
//       return false;                                             // stops iteration
//     });
//   > by_letter.remove('b', 'bar');                               // removes 'bar' from the collection of things starting with b

// The on-disk format for indexes is a bit complex. There's a great paper by the Tokutek guys that describes what they call 'fractal trees', an indexing strategy that is much higher-performance
// than B-trees on disks where seeks are expensive. I may try to implement those for this database, though it will probably be the simplified version presented in their paper rather than the full
// version they've released in their TokuDB product.

// For the moment I'm deferring indexing support. The priority at the moment is to get basic data storage going.

  (function () {
    kevlar.database(name) = ensure_directory_sync(name) -returning-
                              {log: log_generator_for(name), associative: associative_generator_for(name), hourly_log: hourly_log_generator_for(name)},

    where [fs                                   = require('fs'),
           ensure_directory_sync(name)          = fs.statSync(name) -safely- fs.mkdirSync(name, 0755),

           associative_generator_for(db)(table) = ensure_directory_sync('#{db}/#{table}')
                                                  -returning- result -effect [it.find(name, f) = result -effect- read_contents(name, f)]

                                                      -where [result(name, value)            = result -effect [set_contents(name, value)],

                                                              djb2_hash(s)                   = bind [h = 5381] in s *![h = (x.charAt(0) * 33 + h) >>> 0] /seq -re- h,
                                                              prefix_directory_for(name)     = (djb2_hash(name) & 0xfff).toString(36),
                                                              with_prefix(name, cc)          = fs.stat('#{db}/#{table}/#{dir}', given [err, stat] [
                                                                                                 err ? fs.mkdir('#{db}/#{table}/#{dir}', 0755, given.nothing in cc(dir)) : cc(dir)])
                                                                                               -where [dir = prefix_directory_for(name)],

                                                              pending_changes                = {},
                                                              timeouts                       = {},
                                                              schedule_commit_for(name)      = timeouts[name] || (timeouts[name] = setTimeout(given.nothing in commit(name), 1000)),

                                                              commit(name)                   = write_file_contents(name, pending_changes[name]) -then- delete timeouts[name]
                                                                                                                                                -then- delete pending_changes[name],

                                                              set_contents(name, value)      = pending_changes[name] = value -effect [schedule_commit_for(name)],

                                                              write_file_contents(name, v)   = with_prefix(name, given.prefix in fs.writeFile(tempfile, JSON.stringify(v), 'utf8',
                                                                                                          detect_errors(delay in fs.rename(tempfile, filename,
                                                                                                          detect_errors(delay in null))))

                                                                                                 -where [filename              = '#{db}/#{table}/#{prefix}/#{name}',
                                                                                                         tempfile              = '#{filename}+',
                                                                                                         detect_errors(f)(err) = err -raise -when.err -then- f()]),

                                                              read_contents(name, f)         = name in pending_changes ? pending_changes[name] :
                                                                                               with_prefix(name, given.prefix in
                                                                                                 fs.readFile('#{db}/#{table}/#{prefix}/#{name}', 'utf8',
                                                                                                             given [err, data] [err /wobbly /when.err, f(JSON.parse(data))]))],

           hourly_log_generator_for(db)(table)  = bind [log = log_generator_for(db)(table)] in
                                                  given [thing] [log(now(), thing)] -effect [it.find(bucket, f) = log.find(bucket, f)]
                                                                                     -where [now() = '#{d.getFullYear()}.#{n(d.getMonth() + 1)}#{n(d.getDay())}.#{n(d.getHours())}00'
                                                                                                     -where [d = new Date(), n(x) = x < 10 ? '0#{x}' : x]],
           log_generator_for(db)(table)         = ensure_directory_sync('#{db}/#{table}')
                                                  -returning- result -effect [it.find(bucket, each) = result -effect- read_bucket_contents(bucket, each)]

                                                      -where [result(bucket, stuff)          = result -effect [append_to_bucket(bucket, JSON.stringify(stuff))],

                                                              append_to_bucket(bucket, line) = queue_for(bucket).push(line) -then- schedule_commit_for(bucket),

                                                              timeouts                       = {},
                                                              schedule_commit_for(bucket)    = timeouts[bucket] || (timeouts[bucket] = setTimeout(given.nothing in commit(bucket), 1000)),

                                                              commit(bucket)                 = write_each_queue_item_for(bucket) -then [delete queues[bucket], delete timeouts[bucket]],
                                                              write_each_queue_item_for(b)   = write_stream_for(b).end(queues[b].join('\n') + '\n', 'utf8'),
                                                              write_stream_for(bucket)       = fs.createWriteStream('#{db}/#{table}/#{bucket}', {flags: 'a', mode: 0644}),

                                                              read_bucket_contents(b, f)     = each_line(fs.createReadStream('#{db}/#{table}/#{b}', {encoding: 'utf8'}), f),

                                                              each_line(stream, f)           = stream -effect [it.on('data', given.piece   in got_pieces(piece.split(/\n/))),
                                                                                                               it.on('end',  given.nothing in f(partial) -when- partial.length)]

                                                                                                       -where [partial        = '',
                                                                                                               got_pieces(ps) = f(partial + ps[0])
                                                                                                                                -then- ps.slice(1, ps.length - 1).forEach(f)
                                                                                                                                -then [partial = ps.length > 1 && ps[ps.length - 1]]],
                                                              queues                         = {},
                                                              queue_for(bucket)              = queues[bucket] || (queues[bucket] = [])]]})();

// Generated by SDoc 




  return kevlar})(require, (function () {var global = typeof kevlar === 'undefined' ? undefined : kevlar; return function () {var k = kevlar; kevlar = global; return k}})());

// Client/server extensions.
// These modules run on both the client and the server, so they provide their own caterwaul invocations rather than being bundled into the above function. They assume that the kevlar global is
// defined.



// Kevlar transport module | Spencer Tipping
// Licensed under the terms of the MIT source code license

// Introduction.
// Most web servers will want to provide some kind of content protection. Sometimes this happens using HTTPS, but that may or may not be necessary depending on the application. I'm implementing
// these encryption and hashing functions to provide a non-HTTPS way to do most authentication-related stuff with reasonable security. (I'm also aware that these libraries are available
// elsewhere, but I'm reimplementing stuff here for fun. It's fine with me if you want to fork the project to use existing open-source solutions instead of my less-performant versions.)

  caterwaul.js_all()(function () {
    kevlar.transport = {} -effect [

// Ascii85 encoding.
// This is similar to base-64 but achieves a better packing ratio. The idea is to take each 32-bit group of characters (in this case two characters, since a character has 16 bits and I'm too lazy
// to do UTF-8 encoding) and arithmetically convert that into five base-85 digits. Each base-85 digit is just ASCII 33 + some number, yielding a high value of 127. This encoder doesn't insert
// checksums or add metadata other than the minimal amount of padding necessary to derive the length of the original string. This implementation differs from the one described at
// http://en.wikipedia.org/wiki/Ascii85 in that it adds at most one null character, since each character is encoded as 16 bits rather than 8.

  it.encode85(s) = encoded -where [powers_of_85    = n[5] *~[n[1, x + 2] /[x * 85]] -seq,
                                   encode_block(n) = n[5] *[String.fromCharCode(33 + n / powers_of_85[4 - x] % 85)] -seq -re- it.join(''),
                                   padded          = s.length & 1 ? s + String.fromCharCode(0) : s,
                                   encoded_string  = n[0, padded.length, 2] *[encode_block((padded.charCodeAt(x) << 16) >>> 0 | padded.charCodeAt(x + 1))] -seq -re- it.join(''),
                                   encoded         = s.length & 1 ? encoded_string.substr(0, encoded_string.length - 2) : encoded_string],

  it.decode85(s) = decoded -where [decode_block(n) = String.fromCharCode(n >>> 16) + String.fromCharCode(n >>> 0 & 0xffff),
                                   block_value(s)  = n[6] /[x * 85 + s.charCodeAt(x0 - 1) - 33] -seq,
                                   padded          = s.length % 5 ? '#{s}uu' : s,
                                   decoded_string  = n[0, padded.length, 5] *[decode_block(block_value(padded.substr(x, 5)))] -seq -re- it.join(''),
                                   decoded         = s.length % 5 ? decoded_string.substr(0, decoded_string.length - 1) : decoded_string]]})();

// Generated by SDoc 




// Generated by SDoc 
