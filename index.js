const express = require('express')
const app = express()
const port = 5000

const mongoose = require('mongoose')
mongoose.connect('mongodb+srv://devzucca:fkdlzm10@boilerplate.piuvp.mongodb.net/BoilerPlate?retryWrites=true&w=majority', {
    useNewUrlParser: true, useUnifiedTopology:true, useCreateIndex: true, useFindAndModify: false}).then(() => console.log('MongoDB connected...'))
.catch(err => console.log(err))

app.get('/', (req, res) => res.send('Hello World! ~ 안녕하세요 devZucca'))

app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))