const cookieParser = require('cookie-parser');
require('dotenv').config({ path: 'variables.env' });
const createServer = require('./createServer');
const db = require('./db');
const jwt = require('jsonwebtoken');


const server = createServer();
// use express middleware to handle cookies
server.express.use(cookieParser());

// decode jwt for user id for each request
server.express.use((req, res, next) => {
    const {token} = req.cookies;
    if(token) {
        const {userId} = jwt.verify(token, process.env.APP_SECRET);
        req.userId = userId;
    }
    next();
})

// create middleware that will populate user on each request
server.express.use(async (req, res, next) => {
    if(!req.userId) return next();
    const user = await db.query.user(
        {where: { id: req.userId } },
        '{ id, permissions, email, name }'
        );
        req.user = user;
        next();
})

server.start({
    cors: {
        credentials: true,
        origin: process.env.FRONTEND_URL,
    },
}, deets => {
    console.log(`Server is now running on port http:/localhost:${deets.port}`);
});
