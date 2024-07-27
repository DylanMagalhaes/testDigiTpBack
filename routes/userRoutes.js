const express = require('express');
const router = express.Router();

const {
    autoRegisterUser,
    login
} = require('../controllers/userController')

router.post('/user', autoRegisterUser)
router.post('/login', login)

module.exports = router;