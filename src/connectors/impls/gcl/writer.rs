// Copyright 2022, The Tremor Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub(crate) mod meta;
mod sink;

use crate::connectors::impls::gcl::writer::sink::GclSink;
use crate::connectors::prelude::*;
use crate::connectors::{Connector, ConnectorBuilder, ConnectorConfig, ConnectorType};
use crate::errors::Error;
use googapis::google::api::MonitoredResource;
use googapis::google::logging::r#type::LogSeverity;
use serde::Deserialize;
use simd_json::OwnedValue;
use std::collections::HashMap;
use tremor_pipeline::ConfigImpl;

#[derive(Deserialize, Clone)]
pub(crate) struct Config {
    // Optional. A default log resource name that is assigned to all log entries in entries that do not specify a value for log_name:
    //
    // "projects/\[PROJECT_ID]/logs/[LOG_ID\]"
    // "organizations/\[ORGANIZATION_ID]/logs/[LOG_ID\]"
    // "billingAccounts/\[BILLING_ACCOUNT_ID]/logs/[LOG_ID\]"
    // "folders/\[FOLDER_ID]/logs/[LOG_ID\]"
    // \[LOG_ID\] must be URL-encoded. For example:
    //
    // "projects/my-project-id/logs/syslog"
    // "organizations/1234567890/logs/cloudresourcemanager.googleapis.com%2Factivity"
    // The permission logging.logEntries.create is needed on each project, organization, billing account, or folder that is receiving new log entries, whether the resource is specified in logName or in an individual log entry.
    pub log_name: Option<String>,

    // Optional. A default monitored resource object that is assigned to all log entries in entries that do not specify a value for resource. Example:
    //
    // { "type": "gce_instance",
    // "labels": {
    //   "zone": "us-central1-a", "instance_id": "00000000000000000000" }}
    #[serde(default = "default_resource")]
    pub resource: Option<simd_json::OwnedValue>,

    // Optional. Whether valid entries should be written even if some other entries fail due to INVALID_ARGUMENT or PERMISSION_DENIED errors. If any entry is not written, then the response status is the error associated with one of the failed entries and the response includes error details keyed by the entries' zero-based index in the entries.write method.
    #[serde(default = "default_partial_success")]
    pub partial_success: bool,

    // Optional. If true, the request should expect normal response, but the entries won't be persisted nor exported. Useful for checking whether the logging API endpoints are working properly before sending valuable data.
    #[serde(default = "default_dry_run")]
    pub dry_run: bool,

    // pub table_id: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,

    // Default Log severity
    #[serde(default = "default_log_severity")]
    pub default_severity: Option<i32>,

    #[serde(default = "default_labels")]
    pub labels: Option<HashMap<String, String>>,
}

fn default_resource() -> Option<simd_json::OwnedValue> {
    None
}

fn default_partial_success() -> bool {
    false
}

fn default_dry_run() -> bool {
    false
}

fn default_connect_timeout() -> u64 {
    0
}

#[allow(clippy::unnecessary_wraps)] // Allow for deserialization from value
fn default_log_severity() -> Option<i32> {
    Some(LogSeverity::Info as i32)
}

fn default_labels() -> Option<HashMap<String, String>> {
    None
}

impl ConfigImpl for Config {}

fn value_to_monitored_resource(
    from: Option<&simd_json::OwnedValue>,
) -> Result<Option<MonitoredResource>> {
    match from {
        None => Ok(None),
        Some(from) => {
            let vt = from.value_type();
            match from {
                OwnedValue::Object(from) => {
                    let kind = from.get("type");
                    let kind = kind.as_str();
                    let maybe_labels = from.get("labels");
                    let labels: HashMap<String, String> = match maybe_labels {
                        None => HashMap::new(),
                        Some(labels) => labels
                            .as_object()
                            .ok_or_else(|| {
                                Error::from(ErrorKind::GclTypeMismatch("Value::Object", vt))
                            })?
                            .iter()
                            .map(|(key, value)| {
                                let key = key.to_string();
                                let value = value.to_string();
                                (key, value)
                            })
                            .collect(),
                    };
                    Ok(Some(MonitoredResource {
                        r#type: match kind {
                            None => "".to_string(),
                            Some(kind) => kind.to_string(),
                        },
                        labels,
                    }))
                }
                _otherwise => Err(Error::from(ErrorKind::GclTypeMismatch(
                    "Value::Object",
                    from.value_type(),
                ))),
            }
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Builder {}

struct Gcl {
    config: Config,
}

#[async_trait::async_trait]
impl Connector for Gcl {
    async fn create_sink(
        &mut self,
        sink_context: SinkContext,
        builder: SinkManagerBuilder,
    ) -> Result<Option<SinkAddr>> {
        let sink = GclSink::new(self.config.clone());

        builder.spawn(sink, sink_context).map(Some)
    }

    fn codec_requirements(&self) -> CodecReq {
        CodecReq::Structured
    }
}

#[async_trait::async_trait]
impl ConnectorBuilder for Builder {
    fn connector_type(&self) -> ConnectorType {
        "gcl_writer".into()
    }

    async fn build(&self, alias: &str, config: &ConnectorConfig) -> Result<Box<dyn Connector>> {
        if let Some(raw_config) = &config.config {
            let config = Config::new(raw_config)?;
            Ok(Box::new(Gcl { config }))
        } else {
            Err(ErrorKind::MissingConfiguration(alias.to_string()).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_to_monitored_resource_conversion() -> Result<()> {
        let mut ok_count = 0;
        let from: OwnedValue = literal!({
            "type": "gce_instance".to_string(),
            "labels": {
              "zone": "us-central1-a",
              "instance_id": "00000000000000000000",
            }
        })
        .into();
        let value = value_to_monitored_resource(Some(&from))?;
        if let Some(value) = value {
            assert_eq!("gce_instance", &value.r#type);
            assert_eq!("us-central1-a".to_string(), value.labels["zone"]);
            assert_eq!(
                "00000000000000000000".to_string(),
                value.labels["instance_id"]
            );
            ok_count += 1;
        } else {
            return Err("Skipped test asserts due to serialization error".into());
        }

        let from: OwnedValue = literal!({
            "type": "gce_instance".to_string(),
        })
        .into();
        let value = value_to_monitored_resource(Some(&from))?;
        if let Some(value) = value {
            assert_eq!(0, value.labels.len());
            ok_count += 1;
        } else {
            return Err("Skipped test asserts due to serialization error".into());
        }

        let from: OwnedValue = literal!({
            "type": "gce_instance".to_string(),
            "labels": [ "snot" ]
        })
        .into();
        let bad_labels = value_to_monitored_resource(Some(&from));
        assert!(bad_labels.is_err());

        let from = literal!(["snot"]);
        let from: OwnedValue = from.into();
        let bad_value = value_to_monitored_resource(Some(&from));
        assert!(bad_value.is_err());

        assert_eq!(2, ok_count);
        Ok(())
    }
}
