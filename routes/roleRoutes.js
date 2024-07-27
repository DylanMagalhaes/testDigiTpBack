const express = require('express');
const router = express.Router();

const {
    initRoles
} = require('../controllers/roleController')

router.get('/role/init', initRoles)

module.exports = router;