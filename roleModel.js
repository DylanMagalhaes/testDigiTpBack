const mongoose = require('mongoose')

const RoleSchema = new mongoose.Schema({
    name: { type: String },
    permissions: { type: [String]},
    deleted: { type: Boolean, default:false }
},{timestamps:true})

const RoleModel = mongoose.model('roles', RoleSchema);

module.exports = RoleModel;