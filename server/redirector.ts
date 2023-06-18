import { readFileSync } from 'node:fs';
import { createServer, Socket } from 'node:net';
import { randomUUID, createHash } from 'node:crypto';
import chalk from 'chalk';

chalk.level = 2;

enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

enum PacketType {
  DATA = "DATA",
  CLOSE = "CLOSE",
  AUTH = "AUTH",
}

const c = {
  level: LogLevel.INFO,
  info: (level: string, ...message: unknown[]) => c.level <= LogLevel.INFO && console.log(chalk`{blue [INFO]  [${level}]} ${message.join(' ')}`),
  warn: (level: string, ...message: unknown[]) => c.level <= LogLevel.WARN && console.log(chalk`{yellow [WARN]  [${level}]} ${message.join(' ')}`),
  error: (level: string, ...message: unknown[]) => c.level <= LogLevel.ERROR && console.log(chalk`{red [ERROR] [${level}]} ${message.join(' ')}`),
  debug: (level: string, ...message: unknown[]) => c.level <= LogLevel.DEBUG && console.log(chalk`{magenta [DEBUG] [${level}]} ${message.join(' ')}`)
}

const config: {
  auth: string;
  separator: string;
  listen: number;
} = JSON.parse(readFileSync('config.json', 'utf8'));

const BACKLOG = 100;
const redirector = createServer();
let ports: null | number[] = null;

const servers = new Map<number, ReturnType<typeof createServer>>();
const connections: Map<UUID, Socket> = new Map();

function isPacketType(data: unknown): data is PacketType {
  return typeof data === "string" && Object.values(PacketType).includes(data as PacketType);
}

function isBuffer(data: unknown): data is Buffer {
  return Buffer.isBuffer(data);
}

function isNumberArray(data: unknown): data is number[] {
  return Array.isArray(data) && typeof data[0] === "number";
}

type UUID = ReturnType<typeof randomUUID>;

function isUUID(data: unknown): data is UUID {
  return typeof data === "string" && data.length === 36 && data.split('-', 6).length === 5;
}

function appendHeader(action: PacketType.CLOSE, id: UUID): Buffer;
function appendHeader(action: PacketType.AUTH, auth: string, ports: number[]): Buffer;
function appendHeader(action: PacketType.DATA, id: UUID, data: Buffer, port: number): Buffer;
function appendHeader(action: PacketType, id: string | UUID, data?: Buffer | number[] | number, port?: number): Buffer {
  switch (action) {
    case PacketType.CLOSE: {
      if (typeof id === "string" && !isUUID(id)) throw new TypeError("Incorrect type for id")
      return Buffer.from(`${action} ${id}${config.separator}`);
    }
    case PacketType.AUTH: {
      if (typeof data === "undefined") throw new Error("Missing data for AUTH packet")
      if (!isNumberArray(data)) throw new TypeError("Incorrect type for AUTH packet")
      return Buffer.from(`${action} ${id} ${data.join(';')}`);
    }
    case PacketType.DATA: {
      if (typeof id === "string" && !isUUID(id)) throw new TypeError("Incorrect type for id")
      if (typeof data === "undefined") throw new Error("Missing data for DATA packet")
      if (!isBuffer(data)) throw new TypeError("Incorrect type for DATA packet")
      const sha1 = createHash('sha1').update(data).digest('hex');
      const sha512 = createHash('sha512').update(data).digest('hex');
      const header = Buffer.from(`${action} ${id} ${port} ${sha1} ${sha512}${config.separator}`);
      return Buffer.concat([header, data]);
    }
  }
}

redirector.on('connection', main_socket => {
  c.info("MAIN", "Received connection from", main_socket.remoteAddress)
  main_socket = main_socket.setNoDelay(true);
  main_socket.on('data', data => {
    if (ports === null) {
      const [action, auth, ports_str] = data.toString('utf8').split(' ');
      if (typeof action === "undefined" || action === "" || !isPacketType(action) || action !== PacketType.AUTH) {
        c.error("MAIN", "Invalid auth packet, closing connection")
        c.debug("MAIN", "Received", data.toString('utf8'))
        c.debug("MAIN", "Action debug:", action, isPacketType(action), action === PacketType.AUTH)
        main_socket.end();
        return;
      }
      if (typeof auth === "undefined" || auth === "" || auth !== config.auth) {
        c.error("MAIN", "Invalid auth packet, closing connection")
        c.debug("MAIN", "Received", auth)
        c.debug("MAIN", "Expected:", config.auth)
        main_socket.end();
        return;
      } else { c.info("MAIN", "Received valid auth packet, parsing port list") }
      if (typeof ports_str === "undefined" || ports_str === "") {
        c.error("MAIN", "Invalid port list, closing connection")
        main_socket.end();
        return;
      }
      else ports = ports_str.split(';').map(port => parseInt(port));

      for (const port of ports) {
        const server = createServer();
        servers.set(port, server);

        server.on('connection', socket => {
          socket.setNoDelay(true);
          c.info(`SOCKET_${port}`, "Received connection from", socket.remoteAddress)
          let id = randomUUID();
          while (connections.has(id)) id = randomUUID();
          connections.set(id, socket);
          c.debug(`SOCKET_${port}`, "Assigned id:", id)

          socket.on('data', data => {
            c.debug(`SOCKET_${port}`, "Received data from", id)
            c.info(`SOCKET_${port}`, id, '->', main_socket.remoteAddress)
            main_socket.write(appendHeader(PacketType.DATA, id, data, port), err => {
              if (err)
                c.error(`SOCKET_${port}/ID_${id}`, "Error while sending data to client:", err)
              else c.debug(`SOCKET_${port}/ID_${id}`, "Sent data to client")
            })
          });

          socket.on('close', () => {
            c.warn(`SOCKET_${port}`, "Closing connection", id)
            main_socket.write(appendHeader(PacketType.CLOSE, id), err => {
              if (err)
                c.error(`SOCKET_${port}/ID_${id}`, "Error while sending data to client:", err)
              else c.debug(`SOCKET_${port}/ID_${id}`, "Sent data to client")
            })
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
      c.debug("MAIN", "Received data from client");
      c.debug("MAIN", "Data:", data.toString('hex').split('').map((char, i) => i % 2 !== 0 ? char + ' ' : char).join(''));
      const [header, ...invalid] = data.toString('utf8').split(config.separator, 1);
      invalid.length && c.warn("MAIN", "Received invalid packet")
      if (typeof header === "undefined" || header === "") {
        c.error("MAIN", "Invalid packet, ignoring")
        return;
      }
      c.debug("MAIN", "Header:", header)
      const [action, id, sha1_dig, sha512_dig] = header.split(' ', 4);
      if (!isUUID(id)) {
        c.error("MAIN", "Invalid id, ignoring")
        return;
      }
      const socket = connections.get(id);
      if (typeof socket === "undefined") {
        c.warn("MAIN", "Connection was already closed, ignoring packet")
        main_socket.write(appendHeader(PacketType.CLOSE, id), err => {
          if (err)
            c.error(`SOCKET_${port}/ID_${id}`, "Error while sending data to client:", err)
          else c.debug(`SOCKET_${port}/ID_${id}`, "Sent data to client")
        })
        return;
      }
      const body = data.subarray(header.length + config.separator.length);
      const port = socket.localPort;
      const sha1 = createHash('sha1').update(body).digest('hex');
      const sha512 = createHash('sha512').update(body).digest('hex');
      c.error(`SOCKET_${port}/${sha1_dig}`, "Buffer sizes:", data.length, data.length - header.length - config.separator.length, body.length)
      if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
        c.error(`SOCKET_${port}`, `Invalid checksum, ignoring (${id}/${sha1_dig})`)
        c.error(`SOCKET_${port}`, "Body length:", body.length)
        c.error(`SOCKET_${port}`, "Expected:", sha1_dig)
        c.error(`SOCKET_${port}`, "Got:     ", sha1)
        c.error(`SOCKET_${port}`, "Expected:", sha512_dig)
        c.error(`SOCKET_${port}`, "Got:     ", sha512)
        return;
      } else {
        c.debug(`SOCKET_${port}`, "Checksums match")
        c.debug(`SOCKET_${port}`, "Body length:", body.length)
        c.debug(`SOCKET_${port}`, "Expected:", sha1_dig)
        c.debug(`SOCKET_${port}`, "Got:     ", sha1)
        c.debug(`SOCKET_${port}`, "Expected:", sha512_dig)
        c.debug(`SOCKET_${port}`, "Got:     ", sha512)
      }
      if (typeof body === "undefined") {
        c.error(`SOCKET_${port}`, "Invalid packet, closing connection")
        return;
      }
      if (!isPacketType(action)) {
        c.error(`SOCKET_${port}/ID_${id}`, "Invalid action, ignoring")
        return;
      }
      socket.write(body, err => {
        if (err)
          c.error(`SOCKET_${port}/ID_${id}`, "Error while sending data to client:", err)
        else c.debug(`SOCKET_${port}/ID_${id}`, "Sent data to client")
      });
      c.info(`SOCKET_${port}`, main_socket.remoteAddress, '->', id)
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
