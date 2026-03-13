const fs = require('fs')
const path = require('path')
let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')

// RS256 requires a private/public key pair. Public key is used for verification.
const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.key'), 'utf8')

module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer")) {
            res.status(403).send("ban chua dang nhap");
            return;
        }
        token = token.split(" ")[1];
        try {
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
            let user = await userController.FindById(result.id)
            if (!user) {
                res.status(403).send("ban chua dang nhap");
            } else {
                req.user = user;
                next()
            }
        } catch (error) {
            res.status(403).send("ban chua dang nhap");
        }

    }
}