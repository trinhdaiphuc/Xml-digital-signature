const express = require("express");
const multer = require("multer");
const signXml = require("./lib/signed-xml");
const validateXml = require("./lib/validate-xml");

const app = express();
const port = process.env.PORT || 3000;

const storage = multer.memoryStorage();
const upload = multer({ storage });

app.use(express.static("./views"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.sendFile("index.html");
});

app.post(
  "/sign",
  upload.fields([
    { name: "xml", maxCount: 1 },
    { name: "private", maxCount: 1 },
    { name: "public", maxCount: 1 },
  ]),
  async (req, res) => {
    if (!req.files || !req.files.xml || !req.files.private || !req.files.public) {
      res.redirect("/");
    }
    const hashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
    const signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const output = await signXml(
      req.files.xml[0].buffer,
      req.files.private[0].buffer,
      req.files.public[0].buffer,
      hashAlgorithm,
      signatureAlgorithm,
    ).catch((e) => {
      console.log("[INFO]:::: e", e);
    });
    res.write(output, "binary");
    res.end(undefined, "binary");
  },
);

app.post("/verify", async (req, res) => {
  if (!req.body || !req.body.data) res.send("Invalid data");
  const result = await validateXml(req.body.data).catch((e) => {
    res.status(500).send(e);
  });
  res.status(200).send(result);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
