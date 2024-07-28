const express = require('express');
const router = express.Router();

const {
    autoRegisterUser,
    login,
    updateUser
} = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/user', autoRegisterUser)
router.post('/login', login)

router.put('/users/:userId/update', authMiddleware, updateUser)

module.exports = router;