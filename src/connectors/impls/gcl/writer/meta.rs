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

use crate::errors::Result;
use beef::Cow;
use googapis::google::logging::{
    r#type::{HttpRequest, LogSeverity},
    v2::{LogEntryOperation, LogEntrySourceLocation},
};
use halfbrown::HashMap;
use std::collections::HashMap as StdHashMap;
use tremor_value::Value;
use value_trait::ValueAccess;

use super::Config;

pub(crate) fn default_log_name(config: &Config) -> String {
    // Use user supplied default, if provided
    if let Some(has_usersupplied_default) = &config.log_name {
        return has_usersupplied_default.clone();
    }

    // Use hardwired `default`, if no user supplied default provided
    "default".to_string()
}

pub(crate) fn log_name(config: &Config, meta: Option<&HashMap<Cow<str>, Value>>) -> String {
    // Override for a specific per event log_name
    if let Some(has_meta) = meta {
        if let Some(log_name) = has_meta.get("log_name") {
            return log_name.to_string();
        }
    }

    default_log_name(config)
}

pub(crate) fn log_severity(
    config: &Config,
    meta: Option<&HashMap<Cow<str>, Value>>,
) -> Result<i32> {
    // Override for a specific per event log_severity
    if let Some(has_meta) = meta {
        if let Some(log_severity) = has_meta.get("log_severity") {
            #[allow(clippy::redundant_else)] // Not redundant
            if let Some(log_severity) = log_severity.as_i32() {
                return Ok(log_severity);
            } else {
                return Err(
                    "Unable to parse `log_severity` from event metadata - expected i32".into(),
                );
            }
        }
    }

    // No per event override, use user supplied default
    if let Some(default_severity) = config.default_severity {
        return Ok(default_severity);
    }

    // No per event or user supplied configuration default, use underlying default
    Ok(LogSeverity::Default as i32)
}

pub(crate) fn insert_id(meta: Option<&HashMap<Cow<str>, Value>>) -> String {
    // Override for a specific per event log_severity
    if let Some(has_meta) = meta {
        if let Some(insert_id) = has_meta.get("insert_id") {
            return insert_id.to_string();
        }
    }

    // NOTE user supplied defaults supported at this time

    "".to_string() // Allow GCL to auto assign a unique id for this event
}

pub(crate) fn http_request(meta: Option<&HashMap<Cow<str>, Value>>) -> Option<HttpRequest> {
    // Override for a specific per event trace
    if let Some(has_meta) = meta {
        if let Some(http_request) = has_meta.get("http_request") {
            return Some(HttpRequest {
                request_method: http_request
                    .get("request_method")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                request_url: http_request
                    .get("request_url")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                request_size: http_request.get("request_size").as_i64().unwrap_or(0),
                status: http_request.get("status").as_i32().unwrap_or(0),
                response_size: http_request.get("response_size").as_i64().unwrap_or(0),
                user_agent: http_request
                    .get("user_agent")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                remote_ip: http_request
                    .get("remote_ip")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                server_ip: http_request
                    .get("server_ip")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                referer: http_request
                    .get("referer")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                latency: match http_request.get("latency").as_u64().unwrap_or(0) {
                    0 => None,
                    otherwise => Some(std::time::Duration::from_nanos(otherwise).into()),
                },
                cache_lookup: http_request.get("cache_lookup").as_bool().unwrap_or(false),
                cache_hit: http_request.get("cache_hit").as_bool().unwrap_or(false),
                cache_validated_with_origin_server: http_request
                    .get("cache_validated_with_origin_server")
                    .as_bool()
                    .unwrap_or(false),
                cache_fill_bytes: http_request.get("cache_fill_bytes").as_i64().unwrap_or(0),
                protocol: http_request
                    .get("protocol")
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }

    None
}

pub(crate) fn default_labels(config: &Config) -> StdHashMap<String, String> {
    let mut labels = StdHashMap::new();

    // Copy over default label entries
    if let Some(config_labels) = &config.labels {
        for (k, v) in config_labels {
            labels.insert(k.clone(), v.to_string());
        }
    }

    labels
}

pub(crate) fn labels(meta: Option<&HashMap<Cow<str>, Value>>) -> StdHashMap<String, String> {
    let mut labels = StdHashMap::new();

    // Override with metadata label entries
    if let Some(has_meta) = meta {
        if let Some(Value::Object(meta_labels)) = has_meta.get("labels") {
            for (k, v) in meta_labels.iter() {
                labels.insert(k.to_string(), v.to_string());
            }
        }
    }

    labels
}

pub(crate) fn operation(meta: Option<&HashMap<Cow<str>, Value>>) -> Option<LogEntryOperation> {
    // Override for a specific per event trace
    if let Some(has_meta) = meta {
        if let Some(operation @ Value::Object(_)) = has_meta.get("operation") {
            return Some(LogEntryOperation {
                id: operation.get("id").as_str().unwrap_or("").to_string(),
                producer: operation.get("producer").as_str().unwrap_or("").to_string(),
                first: operation.get_bool("first").unwrap_or(false),
                last: operation.get_bool("last").unwrap_or(false),
            });
        }
    }

    // Otherwise, None as mapping is optional
    None
}

pub(crate) fn trace(meta: Option<&HashMap<Cow<str>, Value>>) -> String {
    // Override for a specific per event trace
    if let Some(has_meta) = meta {
        if let Some(trace) = has_meta.get("trace") {
            return trace.to_string();
        }
    }

    // NOTE user supplied defaults supported at this time

    "".to_string()
}

pub(crate) fn span_id(meta: Option<&HashMap<Cow<str>, Value>>) -> String {
    // Override for a specific per event span_id
    if let Some(has_meta) = meta {
        if let Some(span_id) = has_meta.get("span_id") {
            return span_id.to_string();
        }
    }

    // NOTE user supplied defaults supported at this time

    "".to_string()
}

pub(crate) fn trace_sampled(meta: Option<&HashMap<Cow<str>, Value>>) -> Result<bool> {
    // Override for a specific per event trace_sampled
    if let Some(has_meta) = meta {
        if let Some(trace_sampled) = has_meta.get("trace_sampled") {
            #[allow(clippy::redundant_else)] // Not redundant
            if let Some(trace_sampled) = trace_sampled.as_bool() {
                return Ok(trace_sampled);
            } else {
                return Err(
                    "Unable to parse `trace_sampled` from event metadata - expected bool".into(),
                );
            }
        }
    }

    // NOTE user supplied defaults supported at this time

    Ok(false)
}

pub(crate) fn source_location(
    meta: Option<&HashMap<Cow<str>, Value>>,
) -> Option<LogEntrySourceLocation> {
    // Override for a specific per event trace
    if let Some(has_meta) = meta {
        if let Some(loc @ Value::Object(_)) = has_meta.get("source_location") {
            return Some(LogEntrySourceLocation {
                file: loc.get("file").as_str().unwrap_or("").to_string(),
                line: loc.get("line").as_i64().unwrap_or(0),
                function: loc.get("function").as_str().unwrap_or("").to_string(),
            });
        }
    }

    // Otherwise, None as mapping is optional
    None
}

#[cfg(test)]
mod test {
    use tremor_value::literal;
    use tremor_value::structurize;

    use super::*;

    macro_rules! fail {
        () => {{
            // NOTE when `no_coverage` is `stable`, enable this line
            //      https://github.com/rust-lang/rust/issues/84605
            //
            // #[no_coverage]
            Err("Unexpected error - structural failure in test".into())
        }};
    }

    #[test]
    fn config_with_defaults_no_overrides() -> Result<()> {
        let config: Config = structurize(literal!({}))?;

        assert_eq!(None, config.log_name);
        assert_eq!(None, config.resource);
        assert_eq!(false, config.partial_success);
        assert_eq!(false, config.dry_run);
        assert_eq!(0, config.connect_timeout);
        assert_eq!(Some(LogSeverity::Info as i32), config.default_severity);
        assert_eq!(None, config.labels);

        Ok(())
    }

    #[test]
    fn config_with_defaults_and_overrides() -> Result<()> {
        let config: Config = structurize(literal!({}))?;
        let meta = literal!({}); // no overrides
        if let Value::Object(meta) = meta {
            assert_eq!("default".to_string(), log_name(&config, Some(&meta)));
            assert_eq!(
                LogSeverity::Info as i32,
                log_severity(&config, Some(&meta))?
            );
            assert_eq!("".to_string(), insert_id(Some(&meta)));
            assert_eq!(None, http_request(Some(&meta)));
            assert_eq!(StdHashMap::new(), labels(Some(&meta)));
            assert_eq!(None, operation(Some(&meta)));
            assert_eq!("".to_string(), trace(Some(&meta)));
            assert_eq!("".to_string(), span_id(Some(&meta)));
            assert_eq!(false, trace_sampled(Some(&meta))?);
            assert_eq!(None, source_location(Some(&meta)));
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn default_log_name_test() -> Result<()> {
        let empty_config = structurize(literal!({}))?;
        assert_eq!("default", &default_log_name(&empty_config));

        let ok_config = structurize(literal!({ "log_name": "snot" }))?;
        assert_eq!("snot", &default_log_name(&ok_config));

        let ko_config: std::result::Result<Config, tremor_value::Error> =
            structurize(literal!({ "log_name": 42 }));
        assert!(ko_config.is_err());
        Ok(())
    }

    #[test]
    fn log_name_overrides() -> Result<()> {
        let empty_config = structurize(literal!({}))?;
        let meta = literal!({
            "log_name": "snot",
        });
        if let Value::Object(meta) = meta {
            assert_eq!("snot".to_string(), log_name(&empty_config, Some(&meta)));
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn log_severity_overrides() -> Result<()> {
        let mut ok_count = 0;
        let mut config: Config = structurize(literal!({}))?;
        let meta = literal!({
            "log_severity": LogSeverity::Debug as i32,
        });
        if let Value::Object(meta) = meta {
            assert_eq!(
                LogSeverity::Debug as i32,
                log_severity(&config, Some(&meta))?
            );
            ok_count += 1;
        }

        let ko_meta = literal!({
            "log_severity": ["snot"],
        });
        if let Value::Object(ko_meta) = ko_meta {
            let result = log_severity(&config, Some(&ko_meta));
            assert!(result.is_err());
            ok_count += 1;
        }

        let no_meta = literal!({});
        config.default_severity = None;
        if let Value::Object(no_meta) = no_meta {
            let result = log_severity(&config, Some(&no_meta));
            assert!(result.is_ok());
            ok_count += 1;
        }

        assert_eq!(3, ok_count);
        Ok(())
    }

    #[test]
    fn insert_id_overrides() -> Result<()> {
        let meta = literal!({
            "insert_id": "1234",
        });
        if let Value::Object(meta) = meta {
            assert_eq!("1234".to_string(), insert_id(Some(&meta)));
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn http_request_overrides() -> Result<()> {
        let mut ok_count = 0;

        let meta = literal!({
            "http_request": {
                "request_method": "GET",
                "request_url": "https://www.tremor.rs/",
                "request_size": 0,
                "status": 200,
                "response_size": 1024,
                "user_agent": "Tremor/v12",
                "remote_ip": "3.125.16.34",
                "server_ip": "127.0.0.1",
                "referer": "",
                "latency": 100_000_000u64,
                "cache_lookup": false,
                "cache_hit": false,
                "cache_validated_with_origin_server": false,
                "cache_fill_bytes": 0,
                "protocol": "websocket"
            }
        });
        if let Value::Object(meta) = meta {
            if let Some(_http_request) = http_request(Some(&meta)) {
                assert_eq!("GET", _http_request.request_method);
                assert_eq!("https://www.tremor.rs/", _http_request.request_url);
                assert_eq!(0, _http_request.request_size);
                assert_eq!(200, _http_request.status);
                assert_eq!(1024, _http_request.response_size);
                assert_eq!("Tremor/v12", _http_request.user_agent);
                assert_eq!("3.125.16.34", _http_request.remote_ip);
                assert_eq!("127.0.0.1", _http_request.server_ip);
                assert_eq!("", _http_request.referer);
                //                assert_eq!(100_000_000u64, _http_request.latency.into());
                assert_eq!(false, _http_request.cache_lookup);
                assert_eq!(false, _http_request.cache_hit);
                assert_eq!(false, _http_request.cache_validated_with_origin_server);
                assert_eq!(0, _http_request.cache_fill_bytes);
                assert_eq!("websocket", _http_request.protocol);
                ok_count += 1;
            }
        };

        let meta = literal!({
            "http_request": {
                "request_method": "GET",
                "request_url": "https://www.tremor.rs/",
                "request_size": 0,
                "status": 200,
                "response_size": 1024,
                "user_agent": "Tremor/v12",
                "remote_ip": "3.125.16.34",
                "server_ip": "127.0.0.1",
                "referer": "",
                "cache_lookup": false,
                "cache_hit": false,
                "cache_validated_with_origin_server": false,
                "cache_fill_bytes": 0,
                "protocol": "websocket"
            }
        });
        if let Value::Object(meta) = meta {
            if let Some(_http_request) = http_request(Some(&meta)) {
                assert_eq!(None, _http_request.latency);
                ok_count += 1;
            }
        }

        assert_eq!(2, ok_count);
        Ok(())
    }

    #[test]
    fn default_labels_test() -> Result<()> {
        let empty_config = structurize(literal!({}))?;
        assert_eq!(StdHashMap::new(), default_labels(&empty_config));

        let ok_config = structurize(literal!({ "labels": { "snot": "badger" } }))?;
        assert_eq!(1, default_labels(&ok_config).len());

        let ko_config: std::result::Result<Config, tremor_value::Error> =
            structurize(literal!({ "labels": "snot" }));
        assert!(ko_config.is_err());

        Ok(())
    }

    #[test]
    fn label_overrides() -> Result<()> {
        let meta = literal!({
            "labels": {
                "badger": "snake"
            }
        });
        if let Value::Object(meta) = meta {
            let labels = labels(Some(&meta));
            let badger = labels.get("badger");
            assert_eq!(None, labels.get("snot"));
            assert_eq!(
                "snake".to_string(),
                badger.unwrap_or(&"fail".to_string()).to_string()
            );
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn operation_overrides() -> Result<()> {
        let meta = literal!({
            "operation": {
                "id": "snot",
                "producer": "badger",
                "first": true,
                "last": true,
            },
        });
        if let Value::Object(meta) = meta {
            assert_eq!(
                Some(LogEntryOperation {
                    id: "snot".to_string(),
                    producer: "badger".to_string(),
                    first: true,
                    last: true
                }),
                operation(Some(&meta))
            );
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn trace_overrides() -> Result<()> {
        let meta = literal!({
            "trace": "snot"
        });
        if let Value::Object(meta) = meta {
            let meta = trace(Some(&meta));
            assert_eq!("snot", meta);
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn span_id_overrides() -> Result<()> {
        let meta = literal!({
            "span_id": "snot"
        });
        if let Value::Object(meta) = meta {
            let meta = span_id(Some(&meta));
            assert_eq!("snot", meta);
            return Ok(());
        }

        fail!()
    }

    #[test]
    fn trace_sampled_overrides() -> Result<()> {
        let meta = literal!({
            "trace_sampled": true
        });
        let mut ok_count = 0;
        if let Value::Object(meta) = meta {
            let meta = trace_sampled(Some(&meta))?;
            assert!(meta);
            ok_count += 1;
        }

        let ko_meta = literal!({
            "trace_sampled": [ "snot" ]
        });
        if let Value::Object(ko_meta) = ko_meta {
            let meta = trace_sampled(Some(&ko_meta));
            assert!(meta.is_err());
            ok_count += 1;
        }

        assert_eq!(2, ok_count);
        Ok(())
    }

    #[test]
    fn source_location_overrides() -> Result<()> {
        let meta = literal!({
            "source_location": {
                "file": "snot",
                "line": 42,
                "function": "badger"
            }
        });
        if let Value::Object(meta) = meta {
            let meta = source_location(Some(&meta));
            assert_eq!(
                Some(LogEntrySourceLocation {
                    file: "snot".to_string(),
                    line: 42i64,
                    function: "badger".to_string()
                }),
                meta
            );
            return Ok(());
        }

        fail!()
    }
}
