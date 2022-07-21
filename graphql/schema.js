const { buildSchema } = require('graphql');

module.exports = buildSchema(`

    type Role {
        _id: ID!
        name: String!
        description: String!
        createdBy: User!
        updatedBy: User!
        createdAt: String!
        updatedAt: String
        users: [User!]!
    }

    type RolesData {
        roles: [Role!]!
        totalRoles: Int!
    }

    input RoleInputData {
        name: String!
        description: String!
    }

    type User {
        _id: ID!
        name: String!
        password: String
        age: Int!
        description: String!
        role: Role!
        imageUrl: String
    }

    input UserInputData {
        name: String!
        password: String
        age: Int!
        description: String!
        roleId: ID!
        imageUrl: String
    }

    type AuthData {
        token: String!
        expiresIn: String!
    }

    type RootQuery {
        login(name: String!, password: String!): AuthData!
        roles(page: Int): RolesData!
        role(id: ID!): Role!
    }

    type RootMutation {
        signup(userInput: UserInputData): User!
        createRole(roleInput: RoleInputData): Role!
        updateRole(id: ID!, roleInput: RoleInputData): Role!
        deleteRole(id: ID!): Boolean
    }

    schema {
        query: RootQuery
        mutation: RootMutation
    }
`);
