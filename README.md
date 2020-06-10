## 1 Model Design

### 1.1 Permissions

A permission represents the ability to do one action. If a user has a role (including `default` role), and this role contains a permission, then we say this user has this permission.

|Key|Type|Description|
|---|---|---|
|subject|String|the subject of the permission|
|action|String|the action of the permission|
|displayName|String|a name for display purpose|
|description|String|a more detailed explanation|
|createdAt|Date|the time to create the permission|
|updatedAt|Date|last time to update the permission|
|deleted|Boolean|whether the permission is deleted|

All fields are required.

### 1.2 Roles

A role consists of several mutually related permissions.

|Key|Type|Description|
|---|---|---|
|name|String|the name of the role|
|permissions|Array\<ObjectId\>|permissions of the role|
|displayName|String|a name for display purpose|
|description|String|a more detailed explanation|
|createdAt|Date|the time to create the role|
|updatedAt|Date|last time to update the role|
|deleted|Boolean|whether the role is deleted|

All fields are required.

### 1.3 Users

|Key|Type|Description|Required|
|---|---|---|---|
|username|String|the username of the user|true|
|password|String|the password of the user|true|
|roles|Array\<ObjectId\>|the roles of the user|true|
|email|String|the email of the user|false|
|nickname|String|the nickname of the user|false|
|avatar|String|path to the avatar|false|
|avatar128|String|path to a square 128x128 avatar|false|
|blocked|Boolean|whether the user is blocked|false|
|createdAt|Date|the time to create the user|true|
|updatedAt|Date|last time to update the user|true|
|deleted|Boolean|whether the user is deleted|true|

### 1.4 Tokens

|Key|Type|Description|
|---|---|---|
|user|ObjectId|user who owns the token|
|issuedAt|Date|the time to create the token|
|expiresAt|Date|the time when the token expires|
|acquireMethod|String|method to acquire the token|
|invoked|bool|whether jwt is invoked|

All fields are required.

### 1.5 Global Settings

There should exists one single document in `globalSettings` document.

|Key|Type|Description|
|---|---|---|
|jwtSecret|Binary|256-byte random secret for JWT|
|createdAt|Date|the time to create the global settings|
|updatedAt|Date|last time to update the global settings|

All fields are required.
