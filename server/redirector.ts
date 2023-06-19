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

const AUTH_BUFFER = Buffer.from(config.auth);
const AUTH_HEX = AUTH_BUFFER.toString('hex');
const SEPARATOR_HEX = Buffer.from(config.separator).toString('hex');

const BACKLOG = 100;
const redirector = createServer();
let ports: null | number[] = null;

const servers = new Map<number, ReturnType<typeof createServer>>();
const connections: Map<UUID, Socket> = new Map();

function formatHex(s?: string): string {
  if (!s) return '';
  for (let i = 2; i < s.length; i += 3) {
    s = s.slice(0, i) + ' ' + s.slice(i);
  }
  return s;
}

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

function buildPacket(action: PacketType.CLOSE, id: UUID): Buffer;
function buildPacket(action: PacketType.AUTH, auth: string, ports: number[]): Buffer;
function buildPacket(action: PacketType.DATA, id: UUID, data: Buffer, port: number): Buffer;
function buildPacket(action: PacketType, id: string | UUID, data?: Buffer | number[] | number, port?: number): Buffer {
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
      return Buffer.concat([header, data, AUTH_BUFFER]);
    }
  }
}

redirector.on('connection', main_socket => {
  let isOnSplitupPhase: [false, null] | [true, Buffer, string, string, Socket] = [false, null];
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
          socket = socket.setNoDelay(true);
          c.info(`SOCKET_${port}`, "Received connection from", socket.remoteAddress)
          let id = randomUUID();
          while (connections.has(id)) id = randomUUID();
          connections.set(id, socket);
          c.debug(`SOCKET_${port}`, "Assigned id:", id)

          socket.on('data', data => {
            c.debug(`SOCKET_${port}`, "Received data from", id)
            c.info(`SOCKET_${port}`, id, '->', main_socket.remoteAddress)
            main_socket.write(buildPacket(PacketType.DATA, id, data, port), err => {
              if (err)
                c.error(`SOCKET_${port}/ID_${id}`, "Error while sending data to client:", err)
              else c.debug(`SOCKET_${port}/ID_${id}`, "Sent data to client")
            })
          });

          socket.on('close', () => {
            c.warn(`SOCKET_${port}`, "Closing connection", id)
            main_socket.write(buildPacket(PacketType.CLOSE, id), err => {
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

          socket.on('drain', () => {
            c.warn(`SOCKET_${port}`, "Connection drained", id)
            socket.resume();
          })
        })

        server.listen(port, '0.0.0.0', BACKLOG, () => {
          c.info(`SOCKET_${port}`, "Opened socket!")
        })
      }
    }
    else {
      let hex_raw = data.toString('hex')
      c.debug("MAIN", "Received data from client");
      if (isOnSplitupPhase[0]) {
        c.debug("MAIN", "Splitup phase hex data:", formatHex(hex_raw))
        if (hex_raw.endsWith(AUTH_HEX)) {
          c.warn("MAIN", "Received dead limit, splitup phase ended")
          isOnSplitupPhase[1] = Buffer.concat([isOnSplitupPhase[1], data.subarray(0, data.length - AUTH_BUFFER.length)]);
          const sha1 = createHash('sha1').update(isOnSplitupPhase[1]).digest('hex');
          const sha512 = createHash('sha512').update(isOnSplitupPhase[1]).digest('hex');
          if (sha1 !== isOnSplitupPhase[2] || sha512 !== isOnSplitupPhase[3]) {
            c.error("MAIN", "Invalid hash, closing connection")
            c.error("MAIN", "Expected:", isOnSplitupPhase[2], isOnSplitupPhase[3])
            c.error("MAIN", "Received:", sha1, sha512)
            isOnSplitupPhase[4].end();
            return;
          }
          c.debug("MAIN", "Received valid hash, sending data to client")
          isOnSplitupPhase[4].write(isOnSplitupPhase[1], err => {
            if (err)
              c.error("MAIN", "Error while sending data to client:", err)
            else c.debug("MAIN", "Sent data to client")
          })
          isOnSplitupPhase = [false, null];
          c.debug("MAIN", "Splitup phase ended")
        }
        else {
          c.debug("MAIN", "Received packet on splitup phase, appending data")
          isOnSplitupPhase[1] = Buffer.concat([isOnSplitupPhase[1], data]);
        }
        return;
      }
      const [header, ...invalid] = data.toString('utf8').split(config.separator, 1);
      const header_hex = data.toString('hex').split(SEPARATOR_HEX, 1)[0]!;
      invalid.length && c.warn("MAIN", "Received invalid packet")
      if (typeof header === "undefined" || header === "") {
        c.error("MAIN", "Invalid packet, ignoring")
        return;
      }
      c.debug("MAIN", "Header:", header)
      const [action, id, sha1_dig, sha512_dig] = header.split(' ', 4);
      const [action_hex, id_hex, sha1_dig_hex, sha512_dig_hex] = header_hex.split('20', 4);
      if (!isUUID(id)) {
        c.error("MAIN", "Invalid id, ignoring")
        return;
      }
      const socket = connections.get(id);
      if (typeof socket === "undefined") {
        c.warn("MAIN", "Connection was already closed, ignoring packet")
        main_socket.write(buildPacket(PacketType.CLOSE, id), err => {
          if (err)
            c.error("MAIN", "Error while sending data to client:", err)
          else c.debug("MAIN", "Sent data to client")
        })
        return;
      }
      if (!hex_raw.endsWith(AUTH_HEX)) {
        c.warn("MAIN", "Just received a split packet, waiting for the rest")
        isOnSplitupPhase = [
          true,
          data.subarray(header.length + config.separator.length),
          sha1_dig ?? '',
          sha512_dig ?? '',
          socket,
        ];
        return;
      }
      const body = data.subarray(header.length + config.separator.length, data.length - AUTH_BUFFER.length);
      const port = socket.localPort;
      hex_raw = hex_raw.replace(header_hex, '');
      hex_raw = hex_raw.replace(Buffer.from(config.separator).toString('hex'), '');
      hex_raw = hex_raw.replace(body.toString('hex'), '');
      hex_raw = hex_raw.replace(AUTH_HEX, '');
      c.debug(`SOCKET_${port}`, "Data:", chalk`{bgGray {red ${formatHex(action_hex)}} {yellow 20} {green ${formatHex(id_hex)}} {yellow 20} {blue ${formatHex(sha1_dig_hex)} {yellow 20} {magenta ${formatHex(sha512_dig_hex)}}} {yellow ${formatHex(SEPARATOR_HEX)}}} ${formatHex(body.toString('hex'))}`);
      if (hex_raw !== '') {
        c.warn(`SOCKET_${port}`, "There is some data left in the buffer")
        c.warn(`SOCKET_${port}`, "Data:", hex_raw.split('').map((C, i) => i % 2 !== 0 ? C + ' ' : C).join('').trim())
      }
      const sha1 = createHash('sha1').update(body).digest('hex');
      const sha512 = createHash('sha512').update(body).digest('hex');
      c.error(`SOCKET_${port}/${sha1_dig}`, "Buffer sizes:", data.byteLength, data.byteLength - header.length - config.separator.length, body.byteLength)
      if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
        c.error(`SOCKET_${port}`, "Body length:", body.length)
        c.error(`SOCKET_${port}`, "Expected:", sha1_dig)
        c.error(`SOCKET_${port}`, "Got:     ", sha1)
        c.error(`SOCKET_${port}`, "Expected:", sha512_dig)
        c.error(`SOCKET_${port}`, "Got:     ", sha512)
        c.error(`SOCKET_${port}`, `Invalid checksum, ignoring (${id}/${sha1_dig})`)
        return;
      } else {
        c.debug(`SOCKET_${port}`, "Checksums match")
      }
      if (typeof body === "undefined") {
        c.error(`SOCKET_${port}`, "Invalid packet, closing connection")
        return;
      }
      if (!isPacketType(action) || action !== PacketType.DATA) {
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
    main_socket.resume();
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
