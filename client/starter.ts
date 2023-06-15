import { readFileSync } from 'fs';
import { connect, Socket } from 'net';

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
  const header = Buffer.from(`${id}${config.separator}`);
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
  const [header, body] = data.toString('binary').split(config.separator);
  if (typeof header === 'undefined' || typeof body === 'undefined') {
    console.log("[MAIN]", "Invalid packet received, ignoring")
    return;
  }
  const [id, port_str] = header.split(' ');
  if (typeof id === 'undefined' || typeof port_str === 'undefined') {
    console.log("[MAIN]", "Invalid packet received, ignoring")
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
  }
  connections.get(id)?.write(body)
})