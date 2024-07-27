const permissionList = [
    "user-read",
    "user-update",
    "user-create",
    "certif-read",
    "certif-create",
    "certif-update",
    "certif-validation"
]

const initRolesData = [
    {
        name:"admin",
        permissions:[
            ...permissionList
        ]
    }
]

module.exports = { initRolesData }