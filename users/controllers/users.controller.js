const UserModel = require('../models/users.model');
const crypto = require('crypto');

exports.insert = (req, res) => {
    let salt = crypto.randomBytes(16).toString('base64');
    let hash = crypto.createHmac('sha512', salt).update(req.body.password).digest("base64");
    req.body.password = salt + "$" + hash;
    req.body.permissionLevel = 1;
    UserModel.createUser(req.body)
        .then((result) => {
            res.status(201).send({id: result._id});
        });
};

exports.list = (req, res) => {
    let limit = req.query.limit && req.query.limit <= 100 ? parseInt(req.query.limit) : 10;
    let page = 0;
    if (req.query) {
        if (req.query.page) {
            req.query.page = parseInt(req.query.page);
            page = Number.isInteger(req.query.page) ? req.query.page : 0;
        }
    }
    UserModel.list(limit, page)
        .then((result) => {
            res.status(200).send(result);
        })
};



exports.getById = (req, res) => {
    UserModel.findById(req.params.userId).then((result) => {
        res.status(200).send(result);
    });
};



exports.patchById = (req, res) => {
    if (req.body.password) {
        let salt = crypto.randomBytes(16).toString('base64');
        let hash = crypto.createHmac('sha512', salt).update(req.body.password).digest("base64");
        req.body.password = salt + "$" + hash;
    }

    UserModel.patchUser(req.params.userId, req.body)
        .then((result) => {
            res.status(204).send({});
        });

};

// In this section, the crypto.createHmac() method is applied
exports.patchById = (req, res) => {
    if (req.body.password){

        let salt = crypto.randomBytes(16).toString('base64');
        // The crypto.createHmac() method is used to create an Hmac object
        // Overall, there is applying a Hashing Algorithm
        // A Hashing Algorithm is a mathematical function that condenses data to a fixed size
        // This Hmac object uses the stated 'algorithm' and 'key'
        // The syntax is crypto.createHmac(algorithm, key, options)
        // This is shown in the example below
        let hash = crypto.createHmac('sha512', salt).update(req.body.password).digest("base64");
        req.body.password = salt + "$" + hash;

        // In the crypto.createHmac() method above, key elements are evident as explained below:
        // 1. algorithm = relies on accessible algorithms for the OpenSSL platform
        // In the Hybrid Encryption system, the algorithm domain includes:
        // MD5, SHA-1, SHA-2, NTLM, and LANMAN
        // sha = stands for Secure Hash Algorith (SHA)
        // As shown in the above syntax, in this case, the used algorithm is sha512
        // Other algorithm options in SHA-2 are SHA-224, SHA-256, SHA-384 and SHA-512
        // SHA-256 - is one of the most popular hash algorithms
    }
    UserModel.patchUser(req.params.userId, req.body).then((result) => {
        res.status(204).send({});
    });
};


exports.removeById = (req, res) => {
    UserModel.removeById(req.params.userId)
        .then((result)=>{
            res.status(204).send({});
        });
};