const cors = require('cors')
const xss = require('xss-clean')
const express = require('express')
const mongoose = require('mongoose')
const app = express()

require('dotenv').config();

const roleRoutes = require('./routes/roleRoutes')
const userRoutes = require('./routes/userRoutes')

app.use(cors())
app.use(xss())
app.use(express.json())

app.use("/", roleRoutes)
app.use('/', userRoutes)


mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        const port = 8093
        app.listen(port);
        console.log("Listening to port " + port)
    })
    .catch((err) => console.log(err));