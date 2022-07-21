const { validationResult } = require('express-validator');

const Role = require('../models/role');

exports.getRoles = (req, res, next) => {
  const currentPage = req.query.page || 1;
  const perPage = 2;
  let totalItems;
  Role.find()
    .countDocuments()
    .then(count => {
      totalItems = count;
      return Role.findWithUsersCount()
        .skip((currentPage - 1) * perPage)
        .limit(perPage);
    })
    .then(roles => {
      res.status(200).json({
        message: 'Fetched roles successfully.',
        result: roles,
        totalItems: totalItems
      });
    })
    .catch(err => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};

exports.getRole = (req, res, next) => {
  const roleId = req.params.id;
  Role.findById(roleId)
    .then(role => {
      if (!role) {
        const error = new Error('Could not find role.');
        error.statusCode = 404;
        throw error;
      }
      res.status(200).json({ message: 'Role fetched.', result: role });
    })
    .catch(err => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};

exports.postRole = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error('Validation failed, entered data is incorrect.');
    error.statusCode = 422;
    error.data = errors.array();
    throw error;
  }
  Role.create({
    name: req.body.name,
    description: req.body.description,
    createdBy: req.userId
  })
    .then(result => {
      res.status(201).json({
        message: 'Role created successfully!',
        result: result
      });
    })
    .catch(err => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};

exports.putRole = (req, res, next) => {
  const roleId = req.params.id;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error('Validation failed, entered data is incorrect.');
    error.statusCode = 422;
    error.data = errors.array();
    throw error;
  }
  Role.findById(roleId)
    .then(role => {
      if (!role) {
        const error = new Error('Could not find role.');
        error.statusCode = 404;
        throw error;
      }
      role.name = req.body.name;
      role.description = req.body.description;
      role.updatedBy = req.userId;
      return role.save();
    })
    .then(result => {
      res.status(200).json({ message: 'Role updated!', result: result });
    })
    .catch(err => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};

exports.deleteRole = (req, res, next) => {
  const roleId = req.params.id;
  Role.findById(roleId)
    .then(role => {
      if (!role) {
        const error = new Error('Could not find role.');
        error.statusCode = 404;
        throw error;
      }
      return Role.findByIdAndRemove(roleId);
    })
    .then(result => {
      res.status(200).json({ message: 'Deleted role.', result: result });
    })
    .catch(err => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};
