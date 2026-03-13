var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')
let {checkLogin} = require('../utils/authHandler')

// RS256 requires a private/public key pair. Private key is used for signing.
const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.key'), 'utf8')

/* POST register */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            let token = jwt.sign({
                id: getUser._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '30d'
            })
            res.send({ token })
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }

});

router.post('/changepassword', checkLogin, ChangePasswordValidator, handleResultValidator, async function (req, res, next) {
    const { oldpassword, newpassword } = req.body;

    if (!bcrypt.compareSync(oldpassword, req.user.password)) {
        res.status(403).send("mat khau cu khong dung");
        return;
    }

    // The schema has a pre-save hook that hashes passwords, so we can store the plain new password.
    req.user.password = newpassword;
    await req.user.save();

    res.send({
        message: "doi mat khau thanh cong"
    });
});

router.get('/me', checkLogin, function (req, res, next) {
    res.send(req.user)
})


module.exports = router;
