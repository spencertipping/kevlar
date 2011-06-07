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

  caterwaul.js_all()(function (exports, require) {
    exports.database(name) = ensure_directory_sync(name) -returning-
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
                                                              queue_for(bucket)              = queues[bucket] || (queues[bucket] = [])]]})(exports, require);

// Generated by SDoc 
