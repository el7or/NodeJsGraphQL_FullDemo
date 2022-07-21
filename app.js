const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const { graphqlHTTP } = require('express-graphql');

const graphqlSchema = require('./graphql/schema');
const graphqlResolver = require('./graphql/resolvers');
const auth = require('./middleware/is-auth');

const app = express();
const port = 8080;

const fileStorage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, 'images') },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, uniqueSuffix + '-' + file.originalname)
    }
})

app.use(bodyParser.json()); // application/json
app.use(multer({ storage: fileStorage }).single('image'));
app.use('/images', express.static(path.join(__dirname, 'images')));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

app.use(auth);

app.put('/post-image', (req, res, next) => {
    if (!req.isAuth) {
        throw new Error('Not authenticated!');
    }
    if (!req.file) {
        return res.status(200).json({ message: 'No file provided!' });
    }
    if (req.body.oldPath) {
        clearImage(req.body.oldPath);
    }
    return res
        .status(201)
        .json({ message: 'File stored.', filePath: req.file.path });
});

app.use(
    '/graphql',
    graphqlHTTP({
        schema: graphqlSchema, // like routes
        rootValue: graphqlResolver, // like controllers
        graphiql: true,
        customFormatErrorFn(err) {
            if (!err.originalError) {
                return err;
            }
            const data = err.originalError.data;
            const message = err.message || 'An error occurred.';
            const code = err.originalError.code || 500;
            return { message: message, status: code, data: data };
        }
    })
);

app.use((error, req, res, next) => {
    console.error(error);
    const status = error.statusCode || 500;
    const message = error.message;
    const errors = error.data;
    res.status(status).json({ message: message, errors: errors });
});

mongoose
    .connect(
        'mongodb+srv://node_test:node_test@cluster0.u9j79.mongodb.net/test-node?retryWrites=true&w=majority'
    )
    .then(result => {
        app.listen(port, () => console.log(`app listening on http://localhost:${port}`));
    })
    .catch(err => console.error(err));