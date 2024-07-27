const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    email: { type: String },
    password: { type: String },
    name: { type: String },
    phone: { type: String },
    connectionCount: { type: Number, default:0 },
    lastConnexion: { type: Date },
    role: {type: mongoose.Schema.Types.ObjectId, ref:'roles'},
    deleted: { type: Boolean, default:false }
},{timestamps:true})

const UserModel = mongoose.model('users', UserSchema);

module.exports = UserModel