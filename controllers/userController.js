const User = require('../models/userModel')
const Role = require('../models/roleModel')
const { verifyToken, encrypt, passwordCompare, generateToken } = require('../utils/functions')

const login = async (req, res) => {
    try {
        const email = req.body?.email;
        const inputPassword = req.body?.password;

        if (email == undefined || email == "") {
            return res.status(400).json({
                success: false,
                message: "Veuillez renseigner un email valide",
                field: 'email'
            })
        }

        const user = await User.findOne({ email: email })
            .populate([
                {
                    path: 'role'
                },
            ])

        if (!user || user?.deleted) {
            return res.status(400).json({
                'success': false,
                'message': 'Identifiants incorrects',
                field: 'email,password'
            })
        }

        const isValidated = await passwordCompare(inputPassword, user.password)

        if (!isValidated) {
            return res.status(400).json({
                'success': false,
                'message': 'Identifiants incorrects',
                field: 'email,password'
            })
        }
        user.connectionCount = (user?.connectionCount ?? 0) + 1
        user.lastConnexion = new Date()
        await user.save()
        const { password, ...displayedUser } = user._doc
        return res.status(200).send({
            'success': true,
            'data': {
                'user': {
                    ...displayedUser,
                    'token': generateToken(user._id)
                },

            },
            'message': 'Connexion réussie'
        });

    } catch (e) {
        return res.status(500).json({
            success: false,
            message: 'Une erreur est survenue : ' + e?.message
        })
    }
}


const autoRegisterUser = async (req, res) => {
    try {
        const userId = await verifyToken(req)
        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "Echec de l'authentification"
            })
        }

        const { role, password, ...body } = req.body
        const roleResult = await Role.findOne({ name: role })
        const existingUser = await User.findOne({ email: body?.email })
        if (existingUser?._id != undefined) {
            return res.status(400).json({
                success: false,
                message: "Existe déjà"
            })
        }

        const hashedPass = await encrypt(password)

        const result = await new User({
            ...body,
            password: hashedPass,
            role: roleResult?._id
        }).save()
        return res.status(200).json({
            'success': true,
            'data': result
        })
    } catch (e) {
        return res.status(500).json({
            'success': false,
            'message': 'Erreur ' + e?.message
        });
    }
}

const updateUser = async (req, res) => {
    const { userId } = req.params;
    const { email, password, newPassword, confirmNewPassword, name, phone } = req.body;
    const currentUser = req.user;

    console.log('Received userId:', userId);
    console.log('Request Body:', req.body);

    try {
        const userToModify = await User.findById(userId);
        console.log('User to modify:', userToModify);

        if (!userToModify) {
            return res.status(404).json({
                success: false,
                message: "Utilisateur non trouvé"
            });
        }

        console.log("userId = " + userToModify._id + " " + "currentUser = " + currentUser._id);

        // Vérification des autorisations
        if (currentUser.role !== 'admin' && currentUser._id.toString() !== userId) {
            return res.status(403).json({
                success: false,
                message: "Non autorisé à modifier cet utilisateur"
            });
        }

        // Update de l'email
        if (email) {
            // Vérification si le mot de passe est fourni
            if (!password) {
                return res.status(400).json({
                    success: false,
                    message: "Mot de passe requis pour changer l'email"
                });
            }
            const isPasswordValid = await passwordCompare(password, userToModify.password);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: "Mot de passe incorrect"
                });
            }
            userToModify.email = email;
        }

        // Update du mot de passe
        if (newPassword && confirmNewPassword) {
            if (newPassword !== confirmNewPassword) {
                return res.status(400).json({
                    success: false,
                    message: "Les nouveaux mots de passe ne correspondent pas"
                });
            }
            const isPasswordValid = await passwordCompare(password, userToModify.password);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: "Mot de passe incorrect"
                });
            }
            const hashedPass = await encrypt(newPassword);
            userToModify.password = hashedPass;
        }

        // Update du nom
        if (name) userToModify.name = name;

        // Update du numéro de téléphone
        if (phone) userToModify.phone = phone;

        // Sauvegarde des modifications dans la DB
        await userToModify.save();

        // Suppression du mot de passe avant de retourner l'utilisateur
        const updatedUser = userToModify.toObject();
        delete updatedUser.password;

        return res.status(200).json({
            success: true,
            message: "Utilisateur mis à jour avec succès",
            data: updatedUser // Retourne les données mises à jour sans le mot de passe
        });

    } catch (error) {
        console.error('Update User Error:', error);
        return res.status(500).json({
            success: false,
            message: "Erreur serveur",
            error: error.message
        });
    }
};



module.exports = {
    autoRegisterUser,
    login,
    updateUser
}