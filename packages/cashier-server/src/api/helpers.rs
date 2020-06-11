use serde::{Serializer, Serialize, Deserializer, Deserialize};
use serde::de::Unexpected;

pub fn serialize_object_id<S>(
    value: &bson::oid::ObjectId,
    serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
    value.to_hex().serialize(serializer)
}

pub fn deserialize_object_id<'de, D>(deserializer: D)
    -> Result<bson::oid::ObjectId, D::Error> where D: Deserializer<'de> {
    let str = String::deserialize(deserializer)?;
    bson::oid::ObjectId::with_string(&str)
        .map_err(|_| serde::de::Error::invalid_value(Unexpected::Str(&str), &"expect 12-byte hex string"))
}