const User = require('../models/userModel')
const Role = require('../models/roleModel')
const { verifyToken, encrypt, passwordCompare, generateToken } = require('../utils/functions')

const login = async(req, res) => {
    try {
        const email = req.body?.email;
        const inputPassword = req.body?.password;

        if(email == undefined || email == "") {
            return res.status(400).json({
                success:false,
                message:"Veuillez renseigner un email valide",
                field:'email'
            })
        }

        const user =await User.findOne({email:email})
        .populate([
            {
                path:'role'
            },
        ])

        if(!user || user?.deleted) {
            return res.status(400).json({
                'success':false,
                'message':'Identifiants incorrects',
                field:'email,password'
            })
        }

        const isValidated = await passwordCompare(inputPassword, user.password)
        
        if(!isValidated) {
            return res.status(400).json({
                'success':false,
                'message':'Identifiants incorrects',
                field:'email,password'
            })
        }
        user.connectionCount = (user?.connectionCount??0)+1
        user.lastConnexion = new Date()
        await user.save()
        const {password, ...displayedUser} = user._doc
        return res.status(200).send({
            'success':true,
            'data':{
                'user':{
                    ...displayedUser,
                    'token':generateToken(user._id)
            },
                
        },
        'message':'Connexion réussie'
        });

    } catch(e) {
        return res.status(500).json({
            success:false,
            message:'Une erreur est survenue : '+e?.message
        })
    }
}


const autoRegisterUser = async(req, res) => {
    try {
        const userId = await verifyToken(req)
        if(!userId) {
            return res.status(401).json({
                success:false,
                message:"Echec de l'authentification"
            })
        }

        const { role, password,  ...body} = req.body
        const roleResult = await Role.findOne({name:role})
        const existingUser = await User.findOne({email:body?.email})
        if(existingUser?._id != undefined) {
            return res.status(400).json({
                success:false,
                message:"Existe déjà"
            })
        }

        const hashedPass = await encrypt(password)

        const result = await new User({
            ...body,
            password:hashedPass,
            role:roleResult?._id
        }).save()
        return res.status(200).json({
            'success':true,
            'data':result
        })
    } catch(e) {
        return res.status(500).json({
            'success':false,
            'message': 'Erreur '+e?.message
        });
    }
}

module.exports = {
    autoRegisterUser,
    login
}