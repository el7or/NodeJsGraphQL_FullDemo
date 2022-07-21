const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const fileHelper = require('../util/file');

Date.prototype.addHours = function (h) {
    this.setTime(this.getTime() + (h * 60 * 60 * 1000));
    return this;
}

exports.login = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error('Validation failed, entered data is incorrect.');
        error.statusCode = 422;
        error.data = errors.array();
        throw error;
    }
    const name = req.body.name;
    const password = req.body.password;
    let loginUser;
    User.findOne({ name: name })
        .populate('roleId', 'name')
        .then(user => {
            if (!user) {
                const error = new Error('A user with this name could not be found.');
                error.statusCode = 401;
                throw error;
            }
            loginUser = user;
            return bcrypt.compare(password, user.password);
        })
        .then(isPasswordMatch => {
            if (!isPasswordMatch) {
                const error = new Error('Wrong password!');
                error.statusCode = 401;
                throw error;
            }
            const token = jwt.sign(
                {
                    name: loginUser.name,
                    userId: loginUser._id.toString(),
                    roleName: loginUser.roleId.name
                },
                'somesupersecretsecret',
                { expiresIn: '1h' }
            );
            res.status(200).json({
                token: token,
                expiresIn: new Date().addHours(1)
                //userId: loginUser._id.toString()
            });
        })
        .catch(err => {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        });
};

exports.signup = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error('Validation failed.');
        error.statusCode = 422;
        error.data = errors.array();
        fileHelper.deleteFile(req.file?.path);
        throw error;
    }
    const name = req.body.name;
    const age = req.body.age;
    const password = req.body.password;
    const description = req.body.description;
    const roleId = req.body.roleId;
    const image = req.file;
    bcrypt.hash(password, 12)
        .then(hashedPassword => {
            return User.create({
                name: name,
                password: hashedPassword,
                age: age,
                description: description,
                roleId: roleId,
                imageUrl: image?.path
            });
        })
        .then(result => {
            res.status(201).json({ message: 'User created!', userId: result._id });
        })
        .catch(err => {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        });
};