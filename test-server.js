import express from "express";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;

app.get("/", (req, res) => {
  res.send("Test server is running!");
});

app.listen(PORT, () => {
  console.log(`✅ Minimal test server is running on http://localhost:${PORT}`);
  console.log("This terminal should NOT exit. Press CTRL+C to stop.");
});