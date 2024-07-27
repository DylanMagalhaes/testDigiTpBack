const Role = require('../models/roleModel')
const { initRolesData } = require('../utils/permissionsData')

const initRoles = async (req, res) => {
    try {
        let createdResult = []
        for (const role of initRolesData) {
            const existing = await Role.findOne({ name: role?.name })
            if (existing) continue

            const newRole = await new Role(role).save()
            if (newRole) createdResult.push(newRole)
        }

        return res.status(200).json({
            success: true,
            message: "Initialisation des rôles réussie",
            data: createdResult
        })
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: 'Une erreur est survenue : ' + err?.message
        })
    }
}

module.exports = { initRoles }