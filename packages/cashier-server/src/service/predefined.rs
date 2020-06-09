pub struct PredefinedPermission(
    pub &'static str, // subject
    pub &'static str, // action
    pub &'static str, // displayName
    pub &'static str, // description
);

// There exists two special id: default and me. Default is for users who are not logged-in.
// Me is for user to get own information.
pub const PREDEFINED_PERMISSIONS: &[PredefinedPermission] = &[
    // CRUD for permissions
    PredefinedPermission("permission", "create", "Create Permission", "Create new permission via POST /api/permissions"),
    PredefinedPermission("permission", "read", "Read Permission", "Read the information of a permission via GET /api/permissions/:id"),
    PredefinedPermission("permission", "list", "List Permission", "List all the permissions matching criteria via GET /api/permissions"),
    PredefinedPermission("permission", "update", "Update Permission", "Update the information of a permission via PATCH /api/permissions/:id"),
    PredefinedPermission("permission", "delete", "Delete Permission", "Delete a permission via DELETE /api/permissions/:id"),
    // CRUD for roles
    PredefinedPermission("role", "create", "Create Role", "Create a new role via POST /api/roles"),
    PredefinedPermission("role", "read", "Read Role", "Read the information of a role via GET /api/roles/:id"),
    PredefinedPermission("role", "list", "List Role", "List all the roles matching criteria via GET /api/roles"),
    PredefinedPermission("role", "update", "Update Role", "Update the information of a role via PATCH /api/roles/:id"),
    PredefinedPermission("role", "delete", "Delete Role", "Delete a role via DELETE /api/roles/:id"),
    // CRUD for users
    PredefinedPermission("user", "create", "Create User", "Create a new user via POST /api/users"),
    PredefinedPermission("user", "read", "Read User", "Read the information of a user via GET /api/users/:id"),
    PredefinedPermission("user", "read-self", "Read Self User", "Read user's own information via GET /api/users/me"),
    PredefinedPermission("user", "list", "List User", "List all the users matching criteria via GET /api/users"),
    PredefinedPermission("user", "update", "Update User", "Update the information of a user via PATCH /api/users/:id"),
    PredefinedPermission("user", "update-self", "Update Self User", "Update user's own information via PATCH /api/users/me"),
    PredefinedPermission("user", "delete", "Delete User", "Delete a user via DELETE /api/users/:id"),
    PredefinedPermission("user", "delete-self", "Delete Self User", "Delete user's own account via DELETE /api/users/me"),
    // CRUD for user's permission
    PredefinedPermission("user-permission", "read", "Read User's Permission", "Read user's permissions via GET /api/users/:id/permissions"),
    PredefinedPermission("user-permission", "read-default", "Read Default User's Permission", "Read default user's permissions via GET /api/users/default/permissions"),
    PredefinedPermission("user-permission", "read-self", "Read Self User's Permission", "Read user's own permissions via GET /api/users/me/permissions"),
    // CRUD for token
    PredefinedPermission("token", "acquire-by-username", "Acquire Token By Username", "Acquire token by username via POST /api/tokens/acquire-by-username"),
    PredefinedPermission("token", "acquire-by-email", "Acquire Token By Email", "Acquire token by email via POST /api/tokens/acquire-by-email"),
    PredefinedPermission("token", "resume", "Resume Token", "Resume a token by providing a valid token via POST /api/tokens/resume"),
    PredefinedPermission("token", "revoke", "Revoke Token", "Revoke all the tokens belong to a user via DELETE /api/tokens/users/:uid"),
    PredefinedPermission("token", "revoke-self", "Revoke Self Token", "Revoke all user's own tokens via DELETE /api/tokens/users/me"),
    PredefinedPermission("token", "list", "List Token", "List all the tokens belong to a user via GET /api/tokens/users/:uid"),
    PredefinedPermission("token", "list-self", "List Self Token", "List all user's own tokens tokens via GET /api/tokens/users/me"),
    PredefinedPermission("token", "revoke-single", "Revoke Single Token", "Revoke one token belong to a user via DELETE /api/token/users/:uid/jti/:jti"),
    PredefinedPermission("token", "revoke-single-self", "Revoke Single Self Token", "Revoke user's own token via DELETE /api/token/users/me/jti/:jti")
];

pub struct PredefinedRole(
    pub &'static str, // name
    pub &'static [(&'static str /* subject */, &'static str /* action */)], // permissions
    pub &'static str, // displayName
    pub &'static str, // description
    pub bool, // whether is acquired by newly registered users
);

pub const PREDEFINED_ROLES: &[PredefinedRole] = &[
    PredefinedRole("permission-admin", &[
        ("permission", "read"),
        ("permission", "list"),
        ("permission", "update"),
        ("role", "create"),
        ("role", "read"),
        ("role", "list"),
        ("role", "update"),
        ("role", "delete"),
    ], "Administrator for Permissions", "Manage permissions and roles", false),
    PredefinedRole("user-admin", &[
        ("permission", "read"),
        ("permission", "list"),
        ("role", "read"),
        ("role", "list"),
        ("user", "create"),
        ("user", "read"),
        ("user", "list"),
        ("user", "update"),
        ("user", "delete"),
        ("user-permission", "read"),
    ], "Administrator for Users", "Manage users", false),
    PredefinedRole("normal-user", &[
        ("user", "read-self"),
        ("user", "update-self"),
        ("user-permission", "read-self"),
        ("token", "revoke-self"),
        ("token", "revoke-single-self"),
    ], "Normal User", "Manage users's own information", true),
    PredefinedRole("default", &[
        ("token", "acquire-by-username"),
        ("token", "acquire-by-email"),
        ("token", "resume"),
    ], "Default", "Every user including not logged-in ones implicitly has this role", false),
];

pub const SUPERUSER_ROLES: &[&'static str] = &[
    "permission-admin",
    "user-admin",
    "normal-user",
];
