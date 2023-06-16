import { readFileSync } from 'node:fs';
import { connect, Socket } from 'node:net';
import { createHash } from 'node:crypto';
import chalk from 'chalk';

const enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

const c = {
  level: LogLevel.DEBUG,
  info: (level: string, ...message: unknown[]) => c.level <= LogLevel.INFO && console.log(chalk`{blue [${level}]} ${message.join(' ')}`),
  warn: (level: string, ...message: unknown[]) => c.level <= LogLevel.WARN && console.log(chalk`{yellow [${level}]} ${message.join(' ')}`),
  error: (level: string, ...message: unknown[]) => c.level <= LogLevel.ERROR && console.log(chalk`{red [${level}]} ${message.join(' ')}`),
  debug: (level: string, ...message: unknown[]) => c.level <= LogLevel.DEBUG && console.log(chalk`{magenta [${level}]} ${message.join(' ')}`)
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
  (s ?? socket).write(config.auth + '\n' + config.targets.map(t => t.port).join(' '))
}

function appendHeader(data: Buffer, id: string): Buffer {
  const string_format = data.toString('binary');
  const sha1 = createHash('sha1').update(string_format).digest('hex');
  const sha512 = createHash('sha512').update(string_format).digest('hex');
  const header = Buffer.from(`${id} ${sha1} ${sha512}${config.separator}`);
  return Buffer.concat([header, data]);
}

const connections: Map<string, Socket> = new Map();

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
  const [header] = data.toString('binary').split(config.separator, 1);
  if (typeof header === 'undefined') {
    c.warn("MAIN", "Invalid header, ignoring")
    return;
  }
  const body = data.subarray(header.length + config.separator.length);
  const [id, port_str, sha1_dig, sha512_dig] = header.split(' ', 4);
  const body_str = body.toString('binary')
  const sha1 = createHash('sha1').update(body_str).digest('hex');
  const sha512 = createHash('sha512').update(body_str).digest('hex');
  const body_len = body.length;
  c.debug(`CONN_${port_str}/${id}`, "Body length:", body_len)
  c.debug(`CONN_${port_str}/${id}`, "Expected:", sha1_dig)
  c.debug(`CONN_${port_str}/${id}`, "Got:     ", sha1)
  c.debug(`CONN_${port_str}/${id}`, "Expected:", sha512_dig)
  c.debug(`CONN_${port_str}/${id}`, "Got:     ", sha512)
  if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
    c.error(`CONN_${port_str}/${id}`, "Invalid checksum, ignoring")
    c.error(`CONN_${port_str}/${id}`, "Body length:", body_len)
    c.error(`CONN_${port_str}/${id}`, "Expected:", sha1_dig)
    c.error(`CONN_${port_str}/${id}`, "Got:     ", sha1)
    c.error(`CONN_${port_str}/${id}`, "Expected:", sha512_dig)
    c.error(`CONN_${port_str}/${id}`, "Got:     ", sha512)
    return;
  } else c.debug(`CONN_${port_str}/${id}`, "Checksums match")
  if (typeof id === 'undefined' || typeof port_str === 'undefined') {
    c.error(`CONN_${port_str}/${id}`, "Invalid packet, ignoring")
    if (typeof id === 'undefined')
      c.error(`CONN_${port_str}/${id}`, "Invalid id, ignoring")
    if (typeof port_str === 'undefined')
      c.error(`CONN_${port_str}/${id}`, "Invalid port, ignoring")
    return;
  }
  const port = parseInt(port_str);
  c.debug(`CONN_${port}/${id}`, "Received data from connection")
  if (!connections.has(id)) {
    const conn_socket = connect(port, config.targets.find(t => t.port === port)?.address ?? 'localhost', () => {
      c.info(`CONN_${port}/${id}`, `Connected to target`)
    })
    connections.set(id, conn_socket)

    conn_socket.on('data', data => {
      c.debug(`CONN_${port}/${id}`, "Received data from target")
      const sha1 = createHash('sha1').update(data.toString('binary')).digest('hex');
      c.debug(`CONN_${port}/${id}/${sha1}`, "Body length:", data.length)
      const new_body = appendHeader(data, id);
      c.debug(`CONN_${port}/${id}/${sha1}`, "Packet length:", new_body.length)
      c.debug(`CONN_${port}/${id}/${sha1}`, "Sending data to client")
      socket.write(new_body)
    })

    conn_socket.on('close', () => {
      c.warn(`CONN_${port}/${id}`, "Closing connection")
      connections.delete(id)
    })

    conn_socket.on('error', data => {
      c.error(`CONN_${port}/${id}`, data.message ?? data)
    })

    conn_socket.on('end', () => {
      conn_socket.destroy();
      c.warn(`CONN_${port}/${id}`, "Connection destroyed")
    })

    conn_socket.on('timeout', () => {
      c.warn(`CONN_${port}/${id}`, "Target timed out, ending connection")
      conn_socket.end();
    })

    conn_socket.on('drain', () => {
      c.warn(`CONN_${port}/${id}`, "Target drained buffer")
    })

    conn_socket.on('ready', () => {
      c.debug(`CONN_${port}/${id}`, "Target ready")
    })
  }
  const success = connections.get(id)?.write(body)
  if (success) c.debug(`CONN_${port}/${id}`, "Successfully flushed buffer to target")
  else c.error(`CONN_${port}/${id}`, "Failed to flush buffer to target:", success)
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