// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Helpers for response enums that must preserve unknown backend values.

use schemars::json_schema;
use serde_json::json;

pub(crate) fn open_string_enum_schema(name: &str, known_values: &[&str]) -> schemars::Schema {
    let mut schema = json_schema!({
        "title": name,
        "type": "string",
        "enum": known_values,
        "description": "Known values are listed here for client generation. Unknown future values may also be returned verbatim."
    });

    if let Some(object) = schema.as_object_mut() {
        object.insert("enum".to_string(), json!(known_values));
    }

    schema
}

macro_rules! open_string_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        $vis enum $name {
            $($variant,)+
            Unknown(String),
        }

        impl $name {
            fn parse(value: &str) -> Self {
                match value {
                    $($value => Self::$variant,)+
                    _ => Self::Unknown(value.to_string()),
                }
            }

            fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(value) => value.as_str(),
                }
            }

            fn known_values() -> &'static [&'static str] {
                &[$($value),+]
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize<'de>>::deserialize(deserializer)?;
                Ok(Self::parse(&value))
            }
        }

        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(
                _generator: &mut schemars::SchemaGenerator,
            ) -> schemars::Schema {
                crate::open_enum::open_string_enum_schema(
                    stringify!($name),
                    Self::known_values(),
                )
            }
        }
    };
}

pub(crate) use open_string_enum;
