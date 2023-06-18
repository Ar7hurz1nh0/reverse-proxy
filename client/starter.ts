import { readFileSync } from 'node:fs';
import { connect, Socket } from 'node:net';
import { createHash, type randomUUID } from 'node:crypto';
import chalk from 'chalk';

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
  level: LogLevel.DEBUG,
  info: (level: string, ...message: unknown[]) => c.level <= LogLevel.INFO && console.log(chalk`{blue [INFO]  [${level}]} ${message.join(' ')}`),
  warn: (level: string, ...message: unknown[]) => c.level <= LogLevel.WARN && console.log(chalk`{yellow [WARN]  [${level}]} ${message.join(' ')}`),
  error: (level: string, ...message: unknown[]) => c.level <= LogLevel.ERROR && console.log(chalk`{red [ERROR] [${level}]} ${message.join(' ')}`),
  debug: (level: string, ...message: unknown[]) => c.level <= LogLevel.DEBUG && console.log(chalk`{magenta [DEBUG] [${level}]} ${message.join(' ')}`)
}

const config: {
  targets: {
    address: string;
    port: number;
  }[];
  separator: string;
  auth: string;
  redirect_to: {
    address: string;
    port: number;
  };
} = JSON.parse(readFileSync('config.json', 'utf8'));

function onConnect(s?: Socket): void {
  c.info("MAIN", "Connected to", `${config.redirect_to.address}:${config.redirect_to.port}`);
  const flushed = (s ?? socket).write(appendHeader(PacketType.AUTH, config.auth, config.targets.map(target => target.port)), err => {
    if (err) c.error("MAIN", "Error while sending AUTH packet:", err);
    else c.debug("MAIN", "Sent AUTH packet");
  });
  if (!flushed) c.warn("MAIN", "Buffer full, did NOT flushed full AUTH packet");
  else c.debug("MAIN", "Flushed full buffer");
}

type UUID = ReturnType<typeof randomUUID>;

function isUUID(data: unknown): data is UUID {
  return typeof data === "string" && data.length === 36 && data.split('-', 6).length === 5;
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

function appendHeader(action: PacketType.CLOSE, id: UUID): Buffer;
function appendHeader(action: PacketType.DATA, id: UUID, data: Buffer): Buffer;
function appendHeader(action: PacketType.AUTH, auth: string, ports: number[]): Buffer;
function appendHeader(action: PacketType, id: UUID | string, data?: Buffer | number[] | number): Buffer {
  switch (action) {
    case PacketType.CLOSE: {
      if (!isUUID(id)) throw new TypeError("Incorrect type for id")
      return Buffer.from(`${action} ${id}${config.separator}`);
    }
    case PacketType.AUTH: {
      if (typeof data === "undefined") throw new Error("Missing data for AUTH packet")
      if (!isNumberArray(data)) throw new Error("Incorrect type for AUTH packet")
      return Buffer.from(`${action} ${id} ${data.join(';')}`);
    }
    case PacketType.DATA: {
      if (!isUUID(id)) throw new TypeError("Incorrect type for id")
      if (typeof data === "undefined") throw new Error("Missing data for DATA packet")
      if (!isBuffer(data)) throw new Error("Incorrect type for DATA packet")
      const sha1 = createHash('sha1').update(data).digest('hex');
      const sha512 = createHash('sha512').update(data).digest('hex');
      const header = Buffer.from(`${action} ${id} ${sha1} ${sha512}${config.separator}`);
      return Buffer.concat([header, data]);
    }
  }
}

const connections: Map<UUID, Socket> = new Map();

c.info("MAIN", "Attempting to connect to", `${config.redirect_to.address}:${config.redirect_to.port}`)
const socket = connect(config.redirect_to.port, config.redirect_to.address, onConnect).setNoDelay(true);

socket.on('error', data => {
  c.error("MAIN", "Error while connecting to target:", data.message ?? data)
  setTimeout(() => {
    c.warn("MAIN", "Attempting to reconnect to target")
    socket.connect(config.redirect_to.port, config.redirect_to.address)
  }, 5000)
})

socket.on('close', error => {
  if (error) return;
  c.warn("MAIN", "Server closed connection, finishing it up")
  socket.end();
})

socket.on('data', data => {
  const [header] = data.toString('utf8').split(config.separator, 1);
  if (typeof header === 'undefined') {
    c.warn("MAIN", "Invalid header, ignoring")
    return;
  }
  const [action, id, port_str, sha1_dig, sha512_dig] = header.split(' ', 5);
  if (!isPacketType(action)) {
    c.error(`CONN_${port_str}/ID_${id}`, "Invalid action, ignoring")
    return;
  }
  if (!isUUID(id)) {
    c.error(`CONN_${port_str}/ID_${id}`, "Invalid id, ignoring")
    return;
  }
  if (action === PacketType.CLOSE) {
    c.info(`CONN_${port_str}/ID_${id}`, "Closing connection")
    connections.get(id)?.end();
    connections.delete(id);
    return;
  }
  if (typeof port_str === 'undefined') {
    c.error(`CONN_${port_str}/ID_${id}`, "Invalid port, ignoring")
    return
  }
  const body = data.subarray(header.length + config.separator.length);
  const sha1 = createHash('sha1').update(body).digest('hex');
  const sha512 = createHash('sha512').update(body).digest('hex');
  const body_len = body.byteLength;
  if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
    c.error(`CONN_${port_str}/ID_${id}`, "Invalid checksum, ignoring")
    c.error(`CONN_${port_str}/ID_${id}`, "Body length:", body_len)
    c.error(`CONN_${port_str}/ID_${id}`, "Expected:", sha1_dig)
    c.error(`CONN_${port_str}/ID_${id}`, "Got:     ", sha1)
    c.error(`CONN_${port_str}/ID_${id}`, "Expected:", sha512_dig)
    c.error(`CONN_${port_str}/ID_${id}`, "Got:     ", sha512)
    return;
  } else {
    c.debug(`CONN_${port_str}/ID_${id}`, "Checksums match")
    c.debug(`CONN_${port_str}/ID_${id}`, "Body length:", body_len)
    c.debug(`CONN_${port_str}/ID_${id}`, "Expected:", sha1_dig)
    c.debug(`CONN_${port_str}/ID_${id}`, "Got:     ", sha1)
    c.debug(`CONN_${port_str}/ID_${id}`, "Expected:", sha512_dig)
    c.debug(`CONN_${port_str}/ID_${id}`, "Got:     ", sha512)
  }
  const port = parseInt(port_str);
  c.debug(`CONN_${port}/ID_${id}`, "Received data from connection")
  if (!connections.has(id)) {
    const conn_socket = connect(port, config.targets.find(t => t.port === port)?.address ?? 'localhost', () => {
      c.info(`CONN_${port}/ID_${id}`, `Connected to target`)
    })
    connections.set(id, conn_socket)

    conn_socket.on('data', data => {
      c.debug(`CONN_${port}/ID_${id}`, "Received data from target")
      const sha1 = createHash('sha1').update(data).digest('hex');
      c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Body length:", data.byteLength)
      c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Sending data to client")
      const flushed = socket.write(appendHeader(PacketType.DATA, id, data), err => {
        if (err)
          c.error(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Error while sending data to client:", err)
        else c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Sent data to client")
      })
      if (!flushed) {
        c.warn(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Client buffer full, pausing target")
        conn_socket.pause();
        socket.once('drain', () => {
          c.warn(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Client buffer drained, resuming target")
          conn_socket.resume();
        })
      }
      else c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Successfully flushed buffer data to client")
    })

    conn_socket.on('close', () => {
      c.warn(`CONN_${port}/ID_${id}`, "Closing connection")
      connections.delete(id)
    })

    conn_socket.on('error', data => {
      c.error(`CONN_${port}/ID_${id}`, data.message ?? data)
    })

    conn_socket.on('end', () => {
      conn_socket.destroy();
      c.warn(`CONN_${port}/ID_${id}`, "Connection destroyed")
    })

    conn_socket.on('timeout', () => {
      c.warn(`CONN_${port}/ID_${id}`, "Target timed out, ending connection")
      conn_socket.end();
    })

    conn_socket.on('drain', () => {
      c.warn(`CONN_${port}/ID_${id}`, "Target drained buffer")
    })

    conn_socket.on('ready', () => {
      c.debug(`CONN_${port}/ID_${id}`, "Target ready")
    })
  }
  const success = connections.get(id)?.write(body, err => {
    if (err)
      c.error(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Error while sending data to client:", err)
    else c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Sent data to client")
  })
  if (success) c.debug(`CONN_${port}/ID_${id}`, "Successfully flushed buffer to target")
  else {
    c.error(`CONN_${port}/ID_${id}`, "Failed to flush buffer to target, pausing client")
    socket.pause();
    socket.once('drain', () => {
      c.error(`CONN_${port}/ID_${id}`, "Client buffer drained, resuming client")
      socket.resume();
    })
  }
})

socket.on('end', () => {
  socket.destroy();
  c.warn("MAIN", "Server destroyed")
})

socket.on('timeout', () => {
  c.warn("MAIN", "Server timed out, ending connection")
  socket.end();
})

socket.on('drain', () => {
  c.warn("MAIN", "Server drained buffer")
})

socket.on('ready', () => {
  c.info("MAIN", "Server ready")
})

socket.on('error', data => {
  c.error("MAIN", data.message ?? data)
})