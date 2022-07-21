const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const Role = require('../models/role');
const { deleteFile } = require('../util/file');

Date.prototype.addHours = function (h) {
  this.setTime(this.getTime() + (h * 60 * 60 * 1000));
  return this;
}

module.exports = {
  login: async function ({ name, password }) {
    const user = await User.findOne({ name: name }).populate('roleId', 'name');
    if (!user) {
      const error = new Error('User not found.');
      error.code = 401;
      throw error;
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      const error = new Error('Password is incorrect.');
      error.code = 401;
      throw error;
    }
    const token = jwt.sign(
      {
        name: user.name,
        userId: user._id.toString(),
        roleName: user.roleId.name
      },
      'somesupersecretsecret',
      { expiresIn: '1h' }
    );
    return {
      token: token,
      expiresIn: new Date().addHours(1)
      //userId: user._id.toString()
    };
  },
  signup: async function ({ userInput }, req) {
    //   const name = args.userInput.name;
    const errors = [];
    // if (!validator.isEmail(userInput.name)) {
    //   errors.push({ message: 'E-Mail is invalid.' });
    // }
    if (
      validator.isEmpty(userInput.password) ||
      !validator.isLength(userInput.password, { min: 6 })
    ) {
      errors.push({ message: 'Password too short!' });
    }
    if (errors.length > 0) {
      const error = new Error('Invalid input.');
      error.data = errors;
      error.code = 422;
      throw error;
    }
    const existingUser = await User.findOne({ name: userInput.name });
    if (existingUser) {
      const error = new Error('User name exists already!');
      throw error;
    }
    const hashedPassword = await bcrypt.hash(userInput.password, 12);
    const user = new User({
      name: userInput.name,
      age: userInput.age,
      password: hashedPassword,
      description: userInput.description,
      roleId: userInput.roleId
    });
    if (userInput.imageUrl !== 'undefined') {
      user.imageUrl = userInput.imageUrl;
    }
    const createdUser = await user.save();
    return { ...createdUser._doc, _id: createdUser._id.toString() };
  },
  roles: async function ({ page }, req) {
    if (!req.isAuth) {
      const error = new Error('Not authenticated!');
      error.code = 401;
      throw error;
    }
    if (!page) {
      page = 1;
    }
    const perPage = 2;
    const totalRoles = await Role.find().countDocuments();
    const roles = await Role.find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * perPage)
      .limit(perPage)
      .populate(['createdBy', 'updatedBy', 'users'])
    return {
      roles: roles.map(role => {
        return {
          ...role._doc,
          _id: role._id.toString(),
          createdAt: role.createdAt?.toISOString(),
          updatedAt: role.updatedAt?.toISOString()
        };
      }),
      totalRoles: totalRoles
    };
  },
  role: async function ({ id }, req) {
    if (!req.isAuth) {
      const error = new Error('Not authenticated!');
      error.code = 401;
      throw error;
    }
    const role = await Role.findById(id).populate(['createdBy', 'updatedBy', 'users']);
    if (!role) {
      const error = new Error('No role found!');
      error.code = 404;
      throw error;
    }
    return {
      ...role._doc,
      _id: role._id.toString(),
      createdAt: role.createdAt.toISOString(),
      updatedAt: role.updatedAt.toISOString()
    };
  },
  createRole: async function ({ roleInput }, req) {
    if (!req.isAuth) {
      const error = new Error('Not authenticated!');
      error.code = 401;
      throw error;
    }
    const errors = [];
    if (
      validator.isEmpty(roleInput.name) ||
      !validator.isLength(roleInput.name, { min: 3 })
    ) {
      errors.push({ message: 'Name is invalid.' });
    }
    if (
      validator.isEmpty(roleInput.description) ||
      !validator.isLength(roleInput.description, { min: 6 })
    ) {
      errors.push({ message: 'Description is invalid.' });
    }
    if (errors.length > 0) {
      const error = new Error('Invalid input.');
      error.data = errors;
      error.code = 422;
      throw error;
    }
    const role = new Role({
      name: roleInput.name,
      description: roleInput.description,
      createdBy: req.userId
    });
    const createdRole = await (await role.save()).populate(['createdBy', 'updatedBy', 'users']);
    return {
      ...createdRole._doc,
      _id: createdRole._id.toString(),
      createdAt: createdRole.createdAt.toISOString(),
      updatedAt: createdRole.updatedAt.toISOString()
    };
  },
  updateRole: async function ({ id, roleInput }, req) {
    if (!req.isAuth) {
      const error = new Error('Not authenticated!');
      error.code = 401;
      throw error;
    }
    const role = await Role.findById(id);
    if (!role) {
      const error = new Error('No role found!');
      error.code = 404;
      throw error;
    }
    const errors = [];
    if (
      validator.isEmpty(roleInput.name) ||
      !validator.isLength(roleInput.name, { min: 3 })
    ) {
      errors.push({ message: 'Name is invalid.' });
    }
    if (
      validator.isEmpty(roleInput.description) ||
      !validator.isLength(roleInput.description, { min: 6 })
    ) {
      errors.push({ message: 'Description is invalid.' });
    }
    if (errors.length > 0) {
      const error = new Error('Invalid input.');
      error.data = errors;
      error.code = 422;
      throw error;
    }
    role.name = roleInput.name;
    role.description = roleInput.description;
    const updatedRole = await (await role.save()).populate(['createdBy', 'updatedBy', 'users']);
    return {
      ...updatedRole._doc,
      _id: updatedRole._id.toString(),
      createdAt: updatedRole.createdAt.toISOString(),
      updatedAt: updatedRole.updatedAt.toISOString()
    };
  },
  deleteRole: async function ({ id }, req) {
    if (!req.isAuth) {
      const error = new Error('Not authenticated!');
      error.code = 401;
      throw error;
    }
    if (!req.isAdmin) {
      const error = new Error('Not authorized!');
      error.code = 403;
      throw error;
    }
    const role = await Role.findById(id);
    if (!role) {
      const error = new Error('No role found!');
      error.code = 404;
      throw error;
    }
    await Role.findByIdAndRemove(id);
    return true;
  }
};
