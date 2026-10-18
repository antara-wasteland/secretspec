//! Declaration/routing inspection without provider construction or value access.
use crate::provider::OwnedAddress;
use crate::{NativeAddress, Result, Secrets};
use serde::Serialize;

/// Version of the serialized inspection metadata shape (0.22+).
pub const INSPECTION_SCHEMA_VERSION: u32 = 1;

/// Configured coordinates, not a claim of canonical backend identity or existence.
/// Available in the Rust API starting with SecretSpec 0.22.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InspectionAddress {
    Convention {
        project: String,
        profile: String,
        key: String,
    },
    Native {
        coordinates: NativeAddress,
    },
}

/// Static registered capabilities. `None` means not established by metadata.
/// Build availability, access permission and writability of an entry are separate.
/// Disabled Cargo features still have registered contracts; this is no availability probe.
/// Available in the Rust API starting with SecretSpec 0.22.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InspectionCapabilities {
    pub reads: Option<bool>,
    pub deletes: Option<bool>,
}

/// The first configured storage route. Fallback/cache flags describe potential
/// additional effects; no fallback values or provider credentials are inspected.
/// Available in the Rust API starting with SecretSpec 0.22.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InspectionRoute {
    pub provider_uri: String,
    pub address: InspectionAddress,
    pub capabilities: InspectionCapabilities,
    pub has_fallback: bool,
    pub has_cache: bool,
}

/// Value-free effective declaration and routing metadata for one scoped name.
/// No defaults, generation/composition templates or credential sources are exposed.
/// Available in the Rust API starting with SecretSpec 0.22.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NamedInspection {
    pub schema_version: u32,
    pub project: String,
    pub profile: String,
    pub key: String,
    pub required: bool,
    pub as_path: bool,
    pub composed: bool,
    pub extracted: bool,
    pub route: Option<InspectionRoute>,
}

impl Secrets {
    /// Inspect one name using the same scope, profile, override, inheritance and
    /// address planning as resolution, without constructing any provider, reading
    /// values, unlocking a backend, prompting, generating, or performing a write.
    /// `None` means this session does not declare/expose the name. URI metadata is
    /// redacted; configured coordinates are not backend-canonical identity.
    /// This does not report presence or issuer validity. Available in 0.22+.
    pub fn inspect_named(&self, name: &str) -> Result<Option<NamedInspection>> {
        let profile = self.resolve_profile_name(None);
        if !self
            .resolve_profile_secret_names(Some(&profile))?
            .iter()
            .any(|key| key == name)
        {
            return Ok(None);
        }
        let Some(planned) = self.plan_secret(name, &profile, None)? else {
            return Ok(None);
        };
        let route = planned
            .route
            .as_ref()
            .map(|route| -> Result<InspectionRoute> {
                let uri = match route.primary() {
                    Some(uri) => uri.to_owned(),
                    None => {
                        let spec = self.default_provider_spec(None)?;
                        self.override_display_uri(&spec)?
                    }
                };
                let scheme = uri.split(':').next().unwrap_or(&uri);
                let metadata = crate::provider::PROVIDER_REGISTRY
                    .iter()
                    .find(|registration| registration.metadata.schemes.contains(&scheme))
                    .map(|registration| registration.metadata);
                let address = match self.address_for_spec(
                    &planned,
                    route.group_key(),
                    &self.config.project.name,
                    &profile,
                )? {
                    OwnedAddress::Convention {
                        project,
                        profile,
                        key,
                    } => InspectionAddress::Convention {
                        project,
                        profile,
                        key,
                    },
                    OwnedAddress::Native(coordinates) => InspectionAddress::Native { coordinates },
                };
                Ok(InspectionRoute {
                    provider_uri: crate::audit::redact_uri_strict(&uri),
                    address,
                    capabilities: InspectionCapabilities {
                        reads: metadata.map(|metadata| metadata.reads),
                        deletes: metadata.map(|metadata| metadata.deletes),
                    },
                    has_fallback: route.fallback_specs().is_some(),
                    has_cache: route.cache().is_some(),
                })
            })
            .transpose()?;
        Ok(Some(NamedInspection {
            schema_version: INSPECTION_SCHEMA_VERSION,
            project: self.config.project.name.clone(),
            profile,
            key: name.into(),
            required: planned.required(),
            as_path: planned.as_path(),
            composed: planned.is_composed(),
            extracted: planned.extract().is_some(),
            route,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Spec, spec::Secret};

    #[test]
    fn inspection_never_materializes_defaults_or_provider_credentials() {
        let spec = Spec::from_toml(r#"
[project]
name = "inspection-test"
revision = "1.0"
[providers]
cloud = { uri = "bws://00000000-0000-0000-0000-000000000001", credentials = { access_token = { provider = "env", ref = { item = "INSPECTION_MUST_NOT_FETCH" } } } }
[profiles.default]
TOKEN = { description = "Selected", default = "private-default-must-not-leak", refs.cloud = { item = "selected-item", field = "api_key" } }
[profiles.work]
"#).unwrap();
        let (config, _) = spec.into_parts();
        let mut secrets = Secrets::new(config, None, None, Some("default".into()));
        secrets.set_profile("work");
        secrets.set_provider("cloud");
        secrets.set_ignore_ambient_scope(true);
        let inspection = secrets.inspect_named("TOKEN").unwrap().unwrap();
        assert_eq!(inspection.profile, "work");
        assert!(matches!(
            inspection.route.as_ref().unwrap().address,
            InspectionAddress::Native { .. }
        ));
        let encoded = serde_json::to_string(&inspection).unwrap();
        assert!(!encoded.contains("private-default"));
        assert!(!encoded.contains("INSPECTION_MUST_NOT_FETCH"));
        assert_eq!(inspection.route.unwrap().capabilities.reads, Some(true));
        assert!(secrets.inspect_named("UNDECLARED").unwrap().is_none());
    }

    #[test]
    fn composition_has_no_storage_route_and_no_template_in_metadata() {
        let spec = Spec::builder("inspection-composed")
            .secret("TOKEN", Secret::required("Input"))
            .secret(
                "COMBINED",
                Secret::required("Derived").composed("prefix-${TOKEN}"),
            )
            .build()
            .unwrap();
        let (config, _) = spec.into_parts();
        let mut secrets = Secrets::new(config, None, None, Some("default".into()));
        secrets.set_ignore_ambient_scope(true);
        let metadata = secrets.inspect_named("COMBINED").unwrap().unwrap();
        assert!(metadata.composed);
        assert!(metadata.route.is_none());
        assert!(!serde_json::to_string(&metadata).unwrap().contains("prefix"));
    }
}
