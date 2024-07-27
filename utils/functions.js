const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

/**************************************************************************/
/**************************** AUTH FUNCTIONS ******************************/
/**************************************************************************/


// jsonwebtoken generator, with a userId to identify the user
function generateToken(userId) {
    return jwt.sign({ "sub": userId }, process.env.TOKEN_SECRET, {  });
}

function verifyToken(req) {
    let sub = null;
    try {
        jwt.verify(req.headers['authorization'].substring(7), process.env.TOKEN_SECRET, function (tokenErr, decoded) {
            if (tokenErr) throw new Error(tokenErr);
            sub = decoded.sub;
        })
    } catch (e) {
        return null;
    }
    return sub;
}

async function encrypt(string) {
    return new Promise((resolve, reject) => {
        bcrypt.genSalt(10, (err, salt) => {
            if (err) {
                reject(err);
            }
            bcrypt.hash(string, salt, (err, hashedPass) => {
                if (err) {
                    reject(err);
                }
                resolve(hashedPass);
            });
        });
    });
}

async function passwordCompare(inputString, hashedString) {
    return new Promise((resolve, reject) => {
        bcrypt.compare(inputString, hashedString, function(err, isValidated) {
            if(err) {
                reject(err)
                return
            }
            if(isValidated) {
                resolve(true)
            } else {
                reject({message:"Passwords don't match"})
            }
        })
    })
}


module.exports = {
    encrypt,
    generateToken,
    verifyToken,
    passwordCompare,
}