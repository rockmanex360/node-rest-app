require('rootpath')();

const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('./_middleware/error-handler');

app.use(express.urlencoded({
    extended: false
}));

const corsOpts = {
    origin: '*',
  
    methods: [
      'GET',
      'POST',
    ],
  
    allowedHeaders: [
      'Content-Type',
    ],
};

app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOpts));

app.use('/accounts', require('./accounts/accounts.controller'));

app.use('/api-docs', require('./_helpers/swagger'));

app.use(errorHandler);

const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
})