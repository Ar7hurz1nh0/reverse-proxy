import { readFileSync } from 'node:fs';
import { createServer, Socket } from 'node:net';
import { randomUUID, createHash } from 'node:crypto';
import chalk from 'chalk';

chalk.level = 2;

const enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

const c = {
  level: LogLevel.INFO,
  info: (level: string, ...message: unknown[]) => c.level <= LogLevel.INFO && console.log(chalk`{blue [${level}]} ${message.join(' ')}`),
  warn: (level: string, ...message: unknown[]) => c.level <= LogLevel.WARN && console.log(chalk`{yellow [${level}]} ${message.join(' ')}`),
  error: (level: string, ...message: unknown[]) => c.level <= LogLevel.ERROR && console.log(chalk`{red [${level}]} ${message.join(' ')}`),
  debug: (level: string, ...message: unknown[]) => c.level <= LogLevel.DEBUG && console.log(chalk`{magenta [${level}]} ${message.join(' ')}`)
}

const config: {
  auth: string;
  separator: string;
  listen: number;
} = JSON.parse(readFileSync('config.json', 'utf8'));

const MAX_PACKET_SIZE = 384;
const BACKLOG = 100;
const redirector = createServer();
let ports: null | number[] = null;

const servers = new Map<number, ReturnType<typeof createServer>>();
const connections: Map<string, Socket> = new Map();

const shredded_packets: Map<string, Map<number, Buffer>> = new Map();

function appendHeader(data: Buffer, id: ReturnType<typeof randomUUID>, port: number, packet_no?: number, total?: number): Buffer {
  const string_format = data.toString('binary');
  const sha1 = createHash('sha1').update(string_format).digest('hex');
  const sha512 = createHash('sha512').update(string_format).digest('hex');
  const header = Buffer.from(`${id} ${port} ${sha1} ${sha512} ${typeof total !== "undefined" ? ` ${packet_no} ${total}` : ""}${config.separator}`);
  return Buffer.concat([header, data]);
}

redirector.on('connection', main_socket => {
  c.info("MAIN", "Received connection from", main_socket.remoteAddress)
  main_socket.on('data', data => {
    if (ports === null) {
      const packet = data.toString('utf8').split('\n');
      if (typeof packet[0] === "undefined" || packet[0] === "" || packet[0] !== config.auth) {
        c.error("MAIN", "Invalid auth packet, closing connection")
        main_socket.end();
        return;
      } else { c.info("MAIN", "Received valid auth packet, parsing port list") }
      if (typeof packet[1] === "undefined" || packet[1] === "") {
        c.error("MAIN", "Invalid port list, closing connection")
        main_socket.end();
        return;
      }
      else ports = packet[1].split(' ').map(port => parseInt(port));

      for (const port of ports) {
        const server = createServer();
        servers.set(port, server);

        server.on('connection', socket => {
          c.info(`SOCKET_${port}`, "Received connection from", socket.remoteAddress)
          let id = randomUUID();
          while (connections.has(id)) id = randomUUID();
          connections.set(id, socket);
          c.debug(`SOCKET_${port}`, "Assigned id:", id)

          socket.on('data', data => {
            c.debug(`SOCKET_${port}`, "Received data from", id)
            c.info(`SOCKET_${port}`, id, '->', main_socket.remoteAddress)
            if (data.length > MAX_PACKET_SIZE) {
              c.warn(`CONN_${port}/${id}`, "Packet too large, splitting");
              const packets: Buffer[] = [];
              for (let i = 0; i < data.length; i += MAX_PACKET_SIZE) {
                packets.push(data.subarray(i, i + MAX_PACKET_SIZE))
              }
              const total = packets.length;
              packets.forEach((packet, i) => {
                c.debug(`CONN_${port}/${id}`, `Sending packet ${i + 1}/${total}`)
                const new_body = appendHeader(packet, id, i, total);
                socket.write(new_body)
              })
            }
            else main_socket.write(appendHeader(data, id, port))
          });

          socket.on('close', () => {
            c.warn(`SOCKET_${port}`, "Closing connection", id)
            connections.delete(id);
          })

          socket.on('timeout', () => {
            c.warn(`SOCKET_${port}`, "Connection timed out", id)
            socket.end();
          })
        })

        server.listen(port, '0.0.0.0', BACKLOG, () => {
          c.info(`SOCKET_${port}`, "Opened socket!")
        })
      }
    }
    else {
      const [header, ...invalid] = data.toString('binary').split(config.separator, 1);
      invalid.length && c.warn("MAIN", "Received invalid packet")
      if (typeof header === "undefined" || header === "") {
        c.error("MAIN", "Invalid packet, ignoring")
        return;
      }
      c.debug("MAIN", "Header size:", header.length)
      const [id, sha1_dig, sha512_dig, packet_no, total] = header.split(' ', 5);
      if (typeof id === "undefined" || id === "") {
        c.error("MAIN", "Invalid id, ignoring")
        return;
      }
      const socket = connections.get(id);
      if (typeof socket === "undefined") {
        c.warn("MAIN", "Connection was already closed, ignoring packet")
        return;
      }
      const body = data.subarray(header.length + config.separator.length);
      const port = socket.localPort;
      const body_str = body.toString('binary')
      const sha1 = createHash('sha1').update(body_str).digest('hex');
      const sha512 = createHash('sha512').update(body_str).digest('hex');
      c.debug(`SOCKET_${port}`, "Body length:", body.length)
      c.debug(`SOCKET_${port}`, "Expected:", sha1_dig)
      c.debug(`SOCKET_${port}`, "Got:     ", sha1)
      c.debug(`SOCKET_${port}`, "Expected:", sha512_dig)
      c.debug(`SOCKET_${port}`, "Got:     ", sha512)
      c.error(`SOCKET_${port}/${sha1_dig}`, "Buffer sizes:", data.length, data.length - header.length - config.separator.length, body.length)
      if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
        c.error(`SOCKET_${port}`, `Invalid checksum, ignoring (${id}/${sha1_dig})`)
        c.error(`SOCKET_${port}`, "Body length:", body.length)
        c.error(`SOCKET_${port}`, "Expected:", sha1_dig)
        c.error(`SOCKET_${port}`, "Got:     ", sha1)
        c.error(`SOCKET_${port}`, "Expected:", sha512_dig)
        c.error(`SOCKET_${port}`, "Got:     ", sha512)
        return;
      } else c.debug(`SOCKET_${port}`, "Checksums match")
      if (typeof body === "undefined") {
        c.error(`SOCKET_${port}`, "Invalid packet, closing connection")
        return;
      }
      if (typeof packet_no === "undefined" || packet_no === "") {
        socket.write(body);
        c.info(`SOCKET_${port}`, main_socket.remoteAddress, '->', id)
      }
      else {
        c.info(`SOCKET_${port}/${sha1_dig}`, "Got shredded packet", `[${packet_no}/${total}]`)
        if (shredded_packets.has(id)) {
          const s_packet = shredded_packets.get(id)!;
          s_packet.set(parseInt(packet_no), body);
          if (s_packet.size === parseInt(total!)) {
            const packets = []
            for (let i = 0; i < parseInt(total!); i++) {
              packets.push(s_packet.get(i)!)
            }
            socket.write(Buffer.concat(packets));
          }
        } else shredded_packets.set(id, new Map([[parseInt(packet_no), body]]));
      }
    }
  });

  main_socket.on('close', error => {
    if (error) return;
    c.warn("MAIN", "Client closed connection, restarting it");
    ports = null;
    Array.from(servers.entries()).forEach(([port, server]) => {
      server.close(() => {
        c.warn(`SOCKET_${port}`, "Closed socket")
      })
    })
  })

  main_socket.on('timeout', () => {
    c.warn("MAIN", "Client timed out, closing connection");
    main_socket.end();
  })

  main_socket.on('error', error => {
    c.error("MAIN", "Error:", error.message ?? error)
  })

  main_socket.on('drain', () => {
    c.warn("MAIN", "Buffer drained")
  })

  main_socket.on('ready', () => {
    c.debug("MAIN", "Ready")
  })
})

redirector.listen(config.listen, '0.0.0.0', BACKLOG, () => {
  c.info("MAIN", "Opened socket, waiting for auth packet")
})

redirector.on('error', error => {
  c.error("MAIN", "Error:", error.message ?? error)
})

redirector.on('timeout', () => {
  c.warn("MAIN", "Connection timed out, restarting server");
  ports = null;
  Array.from(servers.entries()).forEach(([port, server]) => {
    server.close(() => {
      c.warn(`SOCKET_${port}`, "Closed socket")
    })
  })
})

redirector.on('drop', () => {
  c.warn("MAIN", "Connection dropped, restarting server");
  ports = null;
  Array.from(servers.entries()).forEach(([port, server]) => {
    server.close(() => {
      c.warn(`SOCKET_${port}`, "Closed socket")
    })
  })
})
