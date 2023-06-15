import { readFileSync } from 'fs';
import { createServer, Socket } from 'net';
import { randomUUID, createHash } from 'crypto';

const config: {
  auth: string;
  separator: string;
  listen: number;
} = JSON.parse(readFileSync('config.json', 'utf8'));

const BACKLOG = 100;
const redirector = createServer();
let ports: null | number[] = null;

const servers = new Map<number, ReturnType<typeof createServer>>();
const connections: Map<string, Socket> = new Map();

function appendHeader(data: Buffer, id: ReturnType<typeof randomUUID>, port: number): Buffer {
  const string_format = data.toString('binary');
  const sha1 = createHash('sha1').update(string_format).digest('hex');
  const sha512 = createHash('sha512').update(string_format).digest('hex');
  const header = Buffer.from(`${id} ${port} ${sha1} ${sha512}${config.separator}`);
  return Buffer.concat([header, data]);
}

redirector.on('connection', main_socket => {
  console.log("[MAIN]", "Received connection from", main_socket.remoteAddress)
  main_socket.on('data', data => {
    if (ports === null) {
      const packet = data.toString('utf8').split('\n');
      if (typeof packet[0] === "undefined" || packet[0] === "" || packet[0] !== config.auth) {
        console.log("[MAIN]", "Invalid auth packet, closing connection")
        main_socket.end();
        return;
      } else { console.log("[MAIN]", "Received valid auth packet, parsing port list") }
      if (typeof packet[1] === "undefined" || packet[1] === "") {
        console.log("[MAIN]", "Invalid port list, closing connection")
        main_socket.end();
        return;
      }
      else ports = packet[1].split(' ').map(port => parseInt(port));

      for (const port of ports) {
        const server = createServer();
        servers.set(port, server);

        server.on('connection', socket => {
          console.log(`[SOCKET_${port}]`, "Received connection from", socket.remoteAddress)
          let id = randomUUID();
          while (connections.has(id)) id = randomUUID();
          connections.set(id, socket);
          console.log(`[SOCKET_${port}]`, "Assigned id:", id)

          socket.on('data', data => {
            console.log(`[SOCKET_${port}]`, "Received data from", id)
            console.log(`[SOCKET_${port}]`, id, '->', main_socket.remoteAddress)
            main_socket.write(appendHeader(data, id, port))
          });

          socket.on('close', () => {
            console.log(`[SOCKET_${port}]`, "Closing connection", id)
            connections.delete(id);
          })

          socket.on('timeout', () => {
            console.log(`[SOCKET_${port}]`, "Connection timed out", id)
            socket.end();
          })
        })

        server.listen(port, '0.0.0.0', BACKLOG, () => {
          console.log(`[SOCKET_${port}]`, "Opened socket!")
        })
      }
    }
    else {
      const [header] = data.toString('binary').split(config.separator, 1);
      if (typeof header === "undefined" || header === "") {
        console.log("[MAIN]", "Invalid packet, ignoring")
        return;
      }
      const [id, sha1_dig, sha512_dig] = header.split(' ', 3);
      if (typeof id === "undefined" || id === "") {
        console.log("[MAIN]", "Invalid id, ignoring")
        return;
      }
      const socket = connections.get(id);
      if (typeof socket === "undefined") {
        console.log("[MAIN]", "Connection was already closed, ignoring packet")
        return;
      }
      const body = data.subarray(header.length + config.separator.length);
      const body_str = body.toString('binary')
      const sha1 = createHash('sha1').update(body_str).digest('hex');
      const sha512 = createHash('sha512').update(body_str).digest('hex');
      console.log("[MAIN]", "Expected:", sha1_dig)
      console.log("[MAIN]", "Got:     ", sha1)
      console.log("[MAIN]", "Expected:", sha512_dig)
      console.log("[MAIN]", "Got:     ", sha512)
      if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
        console.log("[MAIN]", "Invalid checksum, ignoring")
        return;
      } else console.log("[MAIN]", "Checksums match")
      if (typeof body === "undefined") {
        console.log("[MAIN]", "Invalid packet, closing connection")
        return;
      }
      socket.write(body);
      console.log("[MAIN]", main_socket.remoteAddress, '->', id)
    }
  });

  main_socket.on('close', error => {
    if (error) return;
    console.log("[MAIN]", "Client closed connection, restarting it");
    ports = null;
    Array.from(servers.entries()).forEach(([port, server]) => {
      server.close(() => {
        console.log(`[SOCKET_${port}]`, "Closed socket")
      })
    })
  })

  main_socket.on('timeout', () => {
    console.log("[MAIN]", "Client timed out, closing connection");
    main_socket.end();
  })

  main_socket.on('error', error => {
    console.log("[MAIN]", "Error:", error.message ?? error)
  })

  main_socket.on('drain', () => {
    console.log("[MAIN]", "Buffer drained")
  })

  main_socket.on('ready', () => {
    console.log("[MAIN]", "Ready")
  })
})

redirector.listen(config.listen, '0.0.0.0', BACKLOG, () => {
  console.log("[MAIN]", "Opened socket, waiting for auth packet")
})

redirector.on('error', error => {
  console.log("[MAIN]", "Error:", error.message ?? error)
})

redirector.on('timeout', () => {
  console.log("[MAIN]", "Connection timed out, restarting server");
  ports = null;
  Array.from(servers.entries()).forEach(([port, server]) => {
    server.close(() => {
      console.log(`[SOCKET_${port}]`, "Closed socket")
    })
  })
})

redirector.on('drop', () => {
  console.log("[MAIN]", "Connection dropped, restarting server");
  ports = null;
  Array.from(servers.entries()).forEach(([port, server]) => {
    server.close(() => {
      console.log(`[SOCKET_${port}]`, "Closed socket")
    })
  })
})
