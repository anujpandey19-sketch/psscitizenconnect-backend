// ---------------- LOGIN (username + password) ----------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post(
      SF_LOGIN_URL,
      new URLSearchParams({
        grant_type: "password",
        client_id: SF_CLIENT_ID,
        client_secret: SF_CLIENT_SECRET,
        username,
        password,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    res.json({ success: true, token: response.data.access_token });
  } catch (err) {
    res.status(401).json({ error: "Invalid username or password" });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
