import { readFileSync } from 'fs';
import { connect, Socket } from 'net';
import { createHash } from 'crypto';

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
  console.log("[MAIN]", "Connected to", `${config.redirect_to.address}:${config.redirect_to.port}`);
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

console.log("[MAIN]", "Attempting to connect to", `${config.redirect_to.address}:${config.redirect_to.port}`)
const socket = connect(config.redirect_to.port, config.redirect_to.address, onConnect)

socket.on('error', data => {
  console.log("[MAIN]", "Error while connecting to target:", data.message ?? data)
  setTimeout(() => {
    console.log("[MAIN]", "Attempting to reconnect to target")
    socket.connect(config.redirect_to.port, config.redirect_to.address)
  }, 5000)
})

socket.on('close', error => {
  if (error) return;
  console.log("[MAIN]", "Server closed connection, finishing it up")
  socket.end();
})

socket.on('data', data => {
  const [header] = data.toString('binary').split(config.separator, 1);
  if (typeof header === 'undefined') {
    console.log("[MAIN]", "Invalid header, ignoring")
    return;
  }
  const body = data.subarray(header.length + config.separator.length);
  const [id, port_str, sha1_dig, sha512_dig] = header.split(' ', 4);
  const body_str = body.toString('binary')
  const sha1 = createHash('sha1').update(body_str).digest('hex');
  const sha512 = createHash('sha512').update(body_str).digest('hex');
  console.log(`[CONN_${port_str}/${id}]`, "Expected:", sha1_dig)
  console.log(`[CONN_${port_str}/${id}]`, "Got:     ", sha1)
  console.log(`[CONN_${port_str}/${id}]`, "Expected:", sha512_dig)
  console.log(`[CONN_${port_str}/${id}]`, "Got:     ", sha512)
  if (sha1 !== sha1_dig || sha512 !== sha512_dig) {
    console.log("[MAIN]", "Invalid checksum, ignoring")
    return;
  } else console.log("[MAIN]", "Checksums match")
  if (typeof id === 'undefined' || typeof port_str === 'undefined') {
    console.log("[MAIN]", "Invalid packet, ignoring")
    if (typeof id === 'undefined')
      console.log("[MAIN]", "Invalid id, ignoring")
    if (typeof port_str === 'undefined')
      console.log("[MAIN]", "Invalid port, ignoring")
    return;
  }
  const port = parseInt(port_str);
  console.log(`[CONN_${port}/${id}]`, "Received data from connection")
  if (!connections.has(id)) {
    const conn_socket = connect(port, config.targets.find(t => t.port === port)?.address ?? 'localhost', () => {
      console.log(`[CONN_${port}/${id}]`, `Connected to target`)
    })
    connections.set(id, conn_socket)

    conn_socket.on('data', data => {
      console.log(`[CONN_${port}/${id}]`, "Received data from target")
      socket.write(appendHeader(data, id))
    })

    conn_socket.on('close', () => {
      console.log(`[CONN_${port}/${id}]`, "Closing connection")
      connections.delete(id)
    })

    conn_socket.on('error', data => {
      console.log(`[CONN_${port}/${id}]`, data.message ?? data)
    })

    conn_socket.on('end', () => {
      conn_socket.destroy();
      console.log(`[CONN_${port}/${id}]`, "Connection destroyed")
    })

    conn_socket.on('timeout', () => {
      console.log(`[CONN_${port}/${id}]`, "Target timed out, ending connection")
      conn_socket.end();
    })

    conn_socket.on('drain', () => {
      console.log(`[CONN_${port}/${id}]`, "Target drained buffer")
    })

    conn_socket.on('ready', () => {
      console.log(`[CONN_${port}/${id}]`, "Target ready")
    })
  }
  const success = connections.get(id)?.write(body)
  if (success) console.log(`[CONN_${port}/${id}]`, "Successfully flushed buffer to target")
  else console.log(`[CONN_${port}/${id}]`, "Failed to flush buffer to target:", success)
})

socket.on('end', () => {
  socket.destroy();
  console.log("[MAIN]", "Server destroyed")
})

socket.on('timeout', () => {
  console.log("[MAIN]", "Server timed out, ending connection")
  socket.end();
})

socket.on('drain', () => {
  console.log("[MAIN]", "Server drained buffer")
})

socket.on('ready', () => {
  console.log("[MAIN]", "Server ready")
})

socket.on('error', data => {
  console.log("[MAIN]", data.message ?? data)
})