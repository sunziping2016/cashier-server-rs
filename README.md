## 1 Model Design

### 1.1 Permissions

A permission represents the ability to do one action. If a user has a role (including `default` role), and this role contains a permission, then we say this user has this permission.

|Key|Type|Description|
|---|---|---|
|subject|String|the subject of the permission|
|action|String|the action of the permission|
|name|String|a name for display purpose|
|description|String|a more detailed explanation|
|createdAt|Date|the time to create the permission|
|updatedAt|Date|last time to update the permission|
|deleted|Boolean|whether the permission is deleted|

