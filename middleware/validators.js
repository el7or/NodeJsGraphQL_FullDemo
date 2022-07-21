const { body } = require('express-validator');

exports.isEmail = (propName) => {
    return body(propName)
        .isEmail()
        .withMessage('Please enter a valid email.')
        .normalizeEmail();
}

exports.isRequired = (propName) => {
    return body(propName)
        .not().isEmpty()
        .withMessage(`This Field is required!`)
        .trim();
}