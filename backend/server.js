const express = require('express')
const dotenv = require('dotenv').config()
const {errorHandler} = require('./midleware/errorMiddleware')
const port = process.env.PORT || 6000


const app = express()

app.use(express.json());
app.use(express.urlencoded( {extended : false}))

app.use('/api/goals', require('./routes/goalRoutes'))

app.use(errorHandler)

app.listen(port,()=>console.log(`Sever started on Port ${port}`));
