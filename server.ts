import express from 'express';

const app = express();

app.use((req, res) => {
  res.send('Hello World!');
  console.log("Received request from", req.ip)
})

app.listen(3000, () => {
  console.log("Listening on port 3000")
})