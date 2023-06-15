import express from 'express';

const app = express();

app.use((req, res) => {
  console.log("Received request from", req.ip)
  res.send('Hello World');
})

app.listen(3000, () => {
  console.log("Listening on port 3000")
})