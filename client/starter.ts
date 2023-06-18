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
  END = "END",
  CLOSE = "CLOSE",
  AUTH = "AUTH",
  SHRED = "SHRED",
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
  (s ?? socket).write(appendHeader(PacketType.AUTH, config.auth, config.targets.map(target => target.port)));
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
function appendHeader(action: PacketType.END, id: UUID): Buffer;
function appendHeader(action: PacketType.DATA, id: UUID, data: Buffer): Buffer;
function appendHeader(action: PacketType.AUTH, auth: string, ports: number[]): Buffer;
function appendHeader(action: PacketType.SHRED, id: UUID, data: Buffer, packet_no: number, total: number): Buffer;
function appendHeader(action: PacketType, id: UUID | string, data?: Buffer | number[] | number, packet_no?: number, total?: number): Buffer {
  switch (action) {
    case PacketType.CLOSE:
      if (!isUUID(id)) throw new TypeError("Incorrect type for id")
      return Buffer.from(`${action} ${id}${config.separator}`);
    case PacketType.END:
      if (!isUUID(id)) throw new TypeError("Incorrect type for id")
      return Buffer.from(`${action} ${id}${config.separator}`);
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
    case PacketType.SHRED: {
      if (!isUUID(id)) throw new TypeError("Incorrect type for id")
      if (typeof data === "undefined") throw new Error("Missing data for SHRED packet")
      if (!isBuffer(data)) throw new Error("Incorrect type for SHRED packet")
      if (typeof packet_no === "undefined") throw new Error("Missing packet_no for SHRED packet")
      if (typeof total === "undefined") throw new Error("Missing total for SHRED packet")
      const sha1 = createHash('sha1').update(data).digest('hex');
      const sha512 = createHash('sha512').update(data).digest('hex');
      const header = Buffer.from(`${action} ${id} ${sha1} ${sha512} ${packet_no} ${total}${config.separator}`);
      return Buffer.concat([header, data]);
    }
  }
}

const MAX_PACKET_SIZE = 384;
const connections: Map<UUID, Socket> = new Map();
const shredded_packets: Map<UUID, Map<number, Buffer>> = new Map();

c.info("MAIN", "Attempting to connect to", `${config.redirect_to.address}:${config.redirect_to.port}`)
const socket = connect(config.redirect_to.port, config.redirect_to.address, onConnect)

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
  const [action, id, port_str, sha1_dig, sha512_dig, packet_no, total] = header.split(' ', 7);
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
  c.debug(`CONN_${port_str}/ID_${id}`, "Body length:", body_len)
  c.debug(`CONN_${port_str}/ID_${id}`, "Expected:", sha1_dig)
  c.debug(`CONN_${port_str}/ID_${id}`, "Got:     ", sha1)
  c.debug(`CONN_${port_str}/ID_${id}`, "Expected:", sha512_dig)
  c.debug(`CONN_${port_str}/ID_${id}`, "Got:     ", sha512)
  if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
    c.error(`CONN_${port_str}/ID_${id}`, "Invalid checksum, ignoring")
    c.error(`CONN_${port_str}/ID_${id}`, "Body length:", body_len)
    c.error(`CONN_${port_str}/ID_${id}`, "Expected:", sha1_dig)
    c.error(`CONN_${port_str}/ID_${id}`, "Got:     ", sha1)
    c.error(`CONN_${port_str}/ID_${id}`, "Expected:", sha512_dig)
    c.error(`CONN_${port_str}/ID_${id}`, "Got:     ", sha512)
    return;
  } else c.debug(`CONN_${port_str}/ID_${id}`, "Checksums match")
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
      const length = data.byteLength
      c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Body length:", length)
      if (length > MAX_PACKET_SIZE) {
        c.warn(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Packet too large, splitting");
        const total = Math.ceil(length / MAX_PACKET_SIZE);
        for (let i = 0; i < length; i += MAX_PACKET_SIZE) {
          const new_body = appendHeader(PacketType.SHRED, id, Buffer.from(data, i, MAX_PACKET_SIZE), i + 1, total);
          c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, `Sending packet ${i + 1}/${total} (${new_body.length} bytes)`)
          socket.write(new_body)
        }
        socket.write(Buffer.from([]))
      }
      else socket.write(appendHeader(PacketType.DATA, id, data))
      c.debug(`CONN_${port}/ID_${id}/SHA1_${sha1}`, "Sending data to client")
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
  if (typeof packet_no === "undefined" || packet_no === "") {
    const success = connections.get(id)?.write(body)
    if (success) c.debug(`CONN_${port}/ID_${id}`, "Successfully flushed buffer to target")
    else c.error(`CONN_${port}/ID_${id}`, "Failed to flush buffer to target:", success)
  }
  else {
    c.info(`SOCKET_${port}/${sha1_dig}`, "Got shredded packet", `[${packet_no}/${total}]`)
    if (shredded_packets.has(id)) {
      const s_packet = shredded_packets.get(id)!;
      s_packet.set(parseInt(packet_no), body);
      if (s_packet.size === parseInt(total!)) {
        c.warn(`SOCKET_${port}/${sha1_dig}`, "Got all shredded packets, reassembling")
        const packets = []
        for (let i = 0; i < parseInt(total!); i++) {
          packets.push(s_packet.get(i)!)
        }
        connections.get(id)?.write(Buffer.concat(packets));
      }
    } else shredded_packets.set(id, new Map([[parseInt(packet_no), body]]));
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