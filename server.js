
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());
app.get('/health', (req, res) => {
res.json({ status: 'BizForce AI is LIVE' });
});
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log('Running on port ' + PORT));

