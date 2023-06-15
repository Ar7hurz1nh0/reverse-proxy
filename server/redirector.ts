import { readFileSync } from 'fs';
import { createServer, Socket } from 'net';
import { randomUUID, createHash } from 'crypto';

const config: {
  auth: string;
  separator: string;
  listen: number;
} = JSON.parse(readFileSync('config.json', 'utf8'));

const starter = createServer();
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

starter.on('connection', main_socket => {
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

        server.listen(port, '0.0.0.0', 50, () => {
          console.log(`[SOCKET_${port}]`, "Opened socket!")
        })
      }
    }
    else {
      const packet = data.toString('binary').split(config.separator);
      if (typeof packet[0] === "undefined" || packet[0] === "") {
        console.log("[MAIN]", "Invalid packet, ignoring")
        return;
      }
      const id = packet[0].split(' ')[0];
      if (typeof id === "undefined" || id === "") {
        console.log("[MAIN]", "Invalid id, ignoring")
        return;
      }
      const socket = connections.get(id);
      if (typeof socket === "undefined") {
        console.log("[MAIN]", "Connection was already closed, ignoring packet")
        return;
      }
      if (typeof packet[1] === "undefined" || packet[1] === "") {
        console.log("[MAIN]", "Invalid packet, closing connection")
        return;
      }
      socket.write(Buffer.from(packet[1], 'binary'));
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
})

starter.listen(config.listen, '0.0.0.0', 50, () => {
  console.log("[MAIN]", "Opened socket, waiting for auth packet")
})