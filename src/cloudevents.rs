// SPDX-FileCopyrightText: 2024 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// [impl->dsn~cloudevents-umessage-mapping~2]

use crate::{
    umessage::{MessageFinalizer, PayloadInjector},
    FieldExtractor, FieldInjector, PayloadExtractor, UAttributesError, UCode, UMessage,
    UMessageError, UMessageType, UPayloadFormat, UPriority, UUri, UUID,
};
use bytes::Bytes;
use protobuf::well_known_types::any::Any;

pub use cloudevents::{cloud_event::CloudEventAttributeValue, CloudEvent};

include!(concat!(env!("OUT_DIR"), "/cloudevents/mod.rs"));

// The _official_ content type to use for CloudEvents serialized using the
// protobuf format.
pub const CONTENT_TYPE_CLOUDEVENTS_PROTOBUF: &str = "application/cloudevents+protobuf";

const CLOUDEVENTS_SPEC_VERSION: &str = "1.0";

const EXTENSION_NAME_COMMSTATUS: &str = "commstatus";
const EXTENSION_NAME_PERMISSION_LEVEL: &str = "plevel";
const EXTENSION_NAME_PFORMAT: &str = "pformat";
const EXTENSION_NAME_PRIORITY: &str = "priority";
const EXTENSION_NAME_REQUEST_ID: &str = "reqid";
const EXTENSION_NAME_SINK: &str = "sink";
const EXTENSION_NAME_TOKEN: &str = "token";
const EXTENSION_NAME_TRACEPARENT: &str = "traceparent";
const EXTENSION_NAME_TTL: &str = "ttl";

struct CloudEventExtractor {
    event: CloudEvent,
}

impl CloudEventExtractor {
    pub fn new(event: CloudEvent) -> Self {
        Self { event }
    }
}

impl PayloadExtractor for CloudEventExtractor {
    fn extract_payload(&self) -> Result<Option<Bytes>, UAttributesError> {
        if self.event.has_binary_data() {
            Ok(Some(Bytes::copy_from_slice(self.event.binary_data())))
        } else if self.event.has_text_data() {
            Ok(Some(self.event.text_data().to_string().into()))
        } else if self.event.has_proto_data() {
            Ok(Some(self.event.proto_data().value.to_vec().into()))
        } else {
            Ok(None)
        }
    }
}

impl FieldExtractor for CloudEventExtractor {
    fn extract_type(&self) -> Result<UMessageType, UAttributesError> {
        UMessageType::try_from_cloudevent_type(&self.event.type_)
    }

    fn extract_id(&self) -> Result<UUID, UAttributesError> {
        self.event
            .id
            .parse::<UUID>()
            .map_err(|e| UAttributesError::parsing_error(e.to_string()))
    }

    fn extract_source(&self) -> Result<UUri, UAttributesError> {
        self.event
            .source
            .parse::<UUri>()
            .map_err(|e| UAttributesError::parsing_error(e.to_string()))
    }

    fn extract_sink(&self) -> Result<Option<UUri>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_SINK) {
            if extension_value.has_ce_uri_ref() {
                return extension_value
                    .ce_uri_ref()
                    .parse::<UUri>()
                    .map_err(|e| UAttributesError::parsing_error(e.to_string()))
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected URI reference for {} extension attribute but found {:?}",
                    EXTENSION_NAME_SINK, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_sink_required(&self) -> Result<UUri, UAttributesError> {
        self.extract_sink().and_then(|sink| {
            sink.ok_or_else(|| {
                UAttributesError::validation_error("missing required sink attribute")
            })
        })
    }

    fn extract_priority(&self) -> Result<Option<UPriority>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_PRIORITY) {
            if extension_value.has_ce_string() {
                return UPriority::try_from_priority_code(extension_value.ce_string())
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected String value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_PRIORITY, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_ttl(&self) -> Result<Option<u32>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_TTL) {
            if extension_value.has_ce_integer() {
                return u32::try_from(extension_value.ce_integer())
                    .map_err(|_e| UAttributesError::parsing_error(format!("expected unsigned Integer value for {} extension attribute but found {:?}", EXTENSION_NAME_TTL, extension_value)))
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected Integer value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_TTL, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_token(&self) -> Result<Option<String>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_TOKEN) {
            if extension_value.has_ce_string() {
                return Ok(Some(extension_value.ce_string().to_string()));
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected String value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_TOKEN, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_permission_level(&self) -> Result<Option<u32>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_PERMISSION_LEVEL) {
            if extension_value.has_ce_integer() {
                return u32::try_from(extension_value.ce_integer())
                    .map_err(|_e| UAttributesError::parsing_error(format!("expected unsigned Integer value for {} extension attribute but found {:?}", EXTENSION_NAME_PERMISSION_LEVEL, extension_value)))
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected Integer value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_PERMISSION_LEVEL, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_request_id(&self) -> Result<Option<UUID>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_REQUEST_ID) {
            if extension_value.has_ce_string() {
                return extension_value
                    .ce_string()
                    .parse::<UUID>()
                    .map_err(|e| UAttributesError::parsing_error(e.to_string()))
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected String value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_REQUEST_ID, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_request_id_required(&self) -> Result<UUID, UAttributesError> {
        self.extract_request_id().and_then(|req_id| {
            req_id.ok_or_else(|| {
                UAttributesError::validation_error("missing required request ID attribute")
            })
        })
    }

    fn extract_commstatus(&self) -> Result<Option<UCode>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_COMMSTATUS) {
            if extension_value.has_ce_integer() {
                return UCode::try_from_i32(extension_value.ce_integer())
                    .map_err(|_e| {
                        UAttributesError::parsing_error(format!(
                            "unsupported commstatus code {:?} in {} extension attribute",
                            extension_value.ce_integer(),
                            EXTENSION_NAME_COMMSTATUS
                        ))
                    })
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected Integer value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_COMMSTATUS, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_traceparent(&self) -> Result<Option<String>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_TRACEPARENT) {
            if extension_value.has_ce_string() {
                return Ok(Some(extension_value.ce_string().to_string()));
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected String value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_TRACEPARENT, extension_value
                )));
            }
        }
        Ok(None)
    }

    fn extract_payload_format(&self) -> Result<Option<UPayloadFormat>, UAttributesError> {
        if let Some(extension_value) = self.event.attributes.get(EXTENSION_NAME_PFORMAT) {
            if extension_value.has_ce_integer() {
                return UPayloadFormat::try_from_i32(extension_value.ce_integer())
                    .map_err(|_e| {
                        UAttributesError::parsing_error(format!(
                            "unsupported payload format {:?} in {} extension attribute",
                            extension_value.ce_integer(),
                            EXTENSION_NAME_PFORMAT
                        ))
                    })
                    .map(Option::Some);
            } else {
                return Err(UAttributesError::parsing_error(format!(
                    "expected Integer value for {} extension attribute but found {:?}",
                    EXTENSION_NAME_PFORMAT, extension_value
                )));
            }
        }
        Ok(None)
    }
}

struct CloudEventInjector {
    event: CloudEvent,
}

impl CloudEventInjector {
    pub fn new(event: CloudEvent) -> Self {
        Self { event }
    }
}

impl PayloadInjector for CloudEventInjector {
    fn inject_payload(
        &mut self,
        payload: Bytes,
        format: UPayloadFormat,
    ) -> Result<(), UAttributesError> {
        match format {
            UPayloadFormat::Protobuf | UPayloadFormat::ProtobufWrappedInAny => {
                // The CloudEvent.set_proto_data function only accepts protobuf messages that are
                // wrapped in an Any, as per the protobuf event format specification.
                // We have no way of efficiently determining, whether the given payload is already
                // wrapped in an Any or not, so we just wrap it in an Any regardless.
                // This means that if the payload is already wrapped in an Any, we will end up with nested Anys.
                // This is not ideal, but it is the only way to ensure that the payload is correctly
                // set on the CloudEvent.
                let data = Any {
                    value: payload.to_vec(),
                    ..Default::default()
                };
                self.event.set_proto_data(data);
            }
            UPayloadFormat::Text | UPayloadFormat::Json => {
                let data = String::from_utf8(payload.to_vec())
                    .map(|v| v.to_string())
                    .map_err(|_e| {
                        UAttributesError::mapping_error("failed to transform payload to string")
                    })?;
                self.event.set_text_data(data);
            }
            UPayloadFormat::Unspecified
            | UPayloadFormat::Raw
            | UPayloadFormat::Shm
            | UPayloadFormat::Someip
            | UPayloadFormat::SomeipTlv => {
                self.event.set_binary_data(payload.to_vec());
            }
        }
        Ok(())
    }
}

impl FieldInjector for CloudEventInjector {
    fn inject_id(&mut self, id: &UUID) -> Result<(), UAttributesError> {
        self.event.id = id.to_hyphenated_string();
        Ok(())
    }

    fn inject_type(&mut self, type_: UMessageType) -> Result<(), UAttributesError> {
        self.event.type_ = type_.to_cloudevent_type();
        Ok(())
    }

    fn inject_source(&mut self, uri: &UUri) -> Result<(), UAttributesError> {
        self.event.source = uri.into();
        Ok(())
    }

    fn inject_sink(&mut self, uri: Option<&UUri>) -> Result<(), UAttributesError> {
        if let Some(sink_uri) = uri {
            let mut val = CloudEventAttributeValue::new();
            val.set_ce_uri_ref(sink_uri.into());
            self.event
                .attributes
                .insert(EXTENSION_NAME_SINK.to_string(), val);
        }
        Ok(())
    }

    fn inject_priority(&mut self, priority: Option<UPriority>) -> Result<(), UAttributesError> {
        let mut val = CloudEventAttributeValue::new();
        if let Some(priority) = priority {
            val.set_ce_string(priority.to_priority_code().to_string());
            self.event
                .attributes
                .insert(EXTENSION_NAME_PRIORITY.to_string(), val);
        }
        Ok(())
    }

    fn inject_ttl(&mut self, ttl: Option<u32>) -> Result<(), UAttributesError> {
        if let Some(ttl) = ttl {
            let v =
                i32::try_from(ttl).map_err(|e| UAttributesError::parsing_error(e.to_string()))?;
            let mut val = CloudEventAttributeValue::new();
            val.set_ce_integer(v);
            self.event
                .attributes
                .insert(EXTENSION_NAME_TTL.to_string(), val);
        }
        Ok(())
    }

    fn inject_token(&mut self, token: Option<&str>) -> Result<(), UAttributesError> {
        let mut val = CloudEventAttributeValue::new();
        if let Some(token) = token {
            val.set_ce_string(token.into());
            self.event
                .attributes
                .insert(EXTENSION_NAME_TOKEN.to_string(), val);
        }
        Ok(())
    }

    fn inject_request_id(&mut self, id: Option<&UUID>) -> Result<(), UAttributesError> {
        let mut val = CloudEventAttributeValue::new();
        if let Some(id) = id {
            val.set_ce_string(id.to_hyphenated_string());
            self.event
                .attributes
                .insert(EXTENSION_NAME_REQUEST_ID.to_string(), val);
        }
        Ok(())
    }

    fn inject_permission_level(&mut self, level: Option<u32>) -> Result<(), UAttributesError> {
        if let Some(level) = level {
            let v =
                i32::try_from(level).map_err(|e| UAttributesError::parsing_error(e.to_string()))?;
            let mut val = CloudEventAttributeValue::new();
            val.set_ce_integer(v);
            self.event
                .attributes
                .insert(EXTENSION_NAME_PERMISSION_LEVEL.to_string(), val);
        }
        Ok(())
    }

    fn inject_traceparent(&mut self, traceparent: Option<&str>) -> Result<(), UAttributesError> {
        if let Some(traceparent) = traceparent {
            let mut val = CloudEventAttributeValue::new();
            val.set_ce_string(traceparent.into());
            self.event
                .attributes
                .insert(EXTENSION_NAME_TRACEPARENT.to_string(), val);
        }
        Ok(())
    }

    fn inject_commstatus(&mut self, status: Option<UCode>) -> Result<(), UAttributesError> {
        if let Some(status) = status.filter(|s| *s != UCode::Ok) {
            let mut val = CloudEventAttributeValue::new();
            val.set_ce_integer(status.value());
            self.event
                .attributes
                .insert(EXTENSION_NAME_COMMSTATUS.to_string(), val);
        }
        Ok(())
    }

    fn inject_payload_format(
        &mut self,
        format: Option<UPayloadFormat>,
    ) -> Result<(), UAttributesError> {
        if let Some(payload_format) = format {
            if payload_format != UPayloadFormat::Unspecified {
                // according to the spec, we only need to set the pformat extension if
                // the payload format is something other than UNSPECIFIED
                let mut val = CloudEventAttributeValue::new();
                val.set_ce_integer(payload_format.as_i32());
                self.event
                    .attributes
                    .insert(EXTENSION_NAME_PFORMAT.to_string(), val);
            }
        }
        Ok(())
    }
}

impl MessageFinalizer for CloudEventInjector {
    type Target = CloudEvent;

    fn finalize(self) -> Result<Self::Target, UAttributesError> {
        // the CloudEvent is already mutated in-place, so we can just return it as the target type
        Ok(self.event)
    }
}

impl TryFrom<&UMessage> for CloudEvent {
    type Error = UMessageError;

    /// Converts a uProtocol message into a CloudEvent using the
    /// [Protobuf Event Format](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/formats/protobuf-format.md).
    ///
    /// # Arguments
    ///
    /// * `message` - The message to create the event from.
    ///               Note that the message is not validated against the uProtocol specification before processing.
    ///
    /// # Returns
    ///
    /// Returns a CloudEvent protobuf with all information from the uProtocol message mapped as defined by the
    /// [uProtocol specification]().
    ///
    /// # Errors
    ///
    /// Returns an error if the given message does not contain the necessary information for creating a CloudEvent.
    fn try_from(message: &UMessage) -> Result<Self, Self::Error> {
        let mut event = CloudEvent::new();
        event.spec_version = CLOUDEVENTS_SPEC_VERSION.into();
        message.map_to_target_fields(CloudEventInjector::new(event))
    }
}

impl TryFrom<CloudEvent> for UMessage {
    type Error = UMessageError;

    /// Converts a CloudEvent to a uProtocol message.
    ///
    /// # Arguments
    ///
    /// * `event` - The CloudEvent to create the message from.
    ///
    /// # Errors
    ///
    /// Returns an error if the given event does not contain the necessary information for creating a uProtocol message.
    /// Also returns an error if the resulting message is not a valid uProtocol message or
    /// [is expired](UMessage::check_expired).
    fn try_from(event: CloudEvent) -> Result<Self, Self::Error> {
        if !CLOUDEVENTS_SPEC_VERSION.eq(&event.spec_version) {
            let msg = format!(
                "expected spec version {} but found {}",
                CLOUDEVENTS_SPEC_VERSION, event.spec_version
            );
            return Err(UAttributesError::validation_error(msg).into());
        }
        let extractor = CloudEventExtractor::new(event);
        UMessage::from_fields(&extractor, true)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cloudevents::CloudEvent;
    use protobuf::{well_known_types::wrappers::StringValue, Message};

    use crate::{UAttributes, UMessageBuilder};

    use super::*;

    const TOPIC: &str = "//my-vehicle/A81B/1/A9BA";
    const METHOD: &str = "//my-vehicle/A000/2/1";
    const REPLY_TO: &str = "//my-vehicle/A81B/1/0";
    const DESTINATION: &str = "//my-vehicle/A000/2/0";
    const PERMISSION_LEVEL: u32 = 5;
    const PRIORITY: UPriority = UPriority::CS4;
    const TTL: u32 = 15_000;
    const TRACEPARENT: &str = "traceparent";
    const DATA: [u8; 4] = [0x00, 0x01, 0x02, 0x03];

    //
    // tests asserting conversion of UMessage -> CloudEvent
    // [utest->dsn~cloudevents-umessage-mapping~2]
    //

    fn assert_standard_cloudevent_attributes(
        event: &CloudEvent,
        message_type: &str,
        uuid: &UUID,
        source: &str,
        sink: Option<String>,
    ) {
        assert_eq!(event.spec_version, CLOUDEVENTS_SPEC_VERSION);
        assert_eq!(event.type_, message_type);
        assert_eq!(event.id, uuid.to_hyphenated_string());
        assert_eq!(event.source.as_str(), source);
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_SINK)
                .map(|v| v.ce_uri_ref().to_owned()),
            sink
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_PRIORITY)
                .map(|v| v.ce_string()),
            Some(PRIORITY.to_priority_code())
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_TTL)
                .map(|v| v.ce_integer() as u32),
            Some(TTL),
            "unexpected TTL"
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_TRACEPARENT)
                .map(|v| v.ce_string()),
            Some(TRACEPARENT)
        );
    }

    #[test]
    fn test_try_from_publish_message_succeeds() {
        let message_id = UUID::build();
        let message =
            UMessageBuilder::publish(UUri::from_str(TOPIC).expect("failed to create topic URI"))
                .with_message_id(message_id.clone())
                .with_priority(PRIORITY)
                .with_ttl(TTL)
                .with_traceparent(TRACEPARENT)
                .build_with_payload("test".as_bytes(), UPayloadFormat::Text)
                .expect("failed to create message");

        let event =
            CloudEvent::try_from(&message).expect("failed to create CloudEvent from UMessage");
        assert_standard_cloudevent_attributes(&event, "up-pub.v1", &message_id, TOPIC, None);
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_PFORMAT)
                .map(|v| v.ce_integer()),
            Some(UPayloadFormat::Text.as_i32())
        );
        assert_eq!(event.text_data(), "test");
    }

    #[test]
    fn test_try_from_notification_message_succeeds() {
        let message_id = UUID::build();
        let message = UMessageBuilder::notification(
            UUri::from_str(TOPIC).expect("failed to create source URI"),
            UUri::from_str(DESTINATION).expect("failed to create sink URI"),
        )
        .with_message_id(message_id.clone())
        .with_priority(PRIORITY)
        .with_ttl(TTL)
        .with_traceparent(TRACEPARENT)
        .build_with_payload("{\"count\": 5}".as_bytes(), UPayloadFormat::Json)
        .expect("failed to create message");

        let event =
            CloudEvent::try_from(&message).expect("failed to create CloudEvent from UMessage");
        assert_standard_cloudevent_attributes(
            &event,
            "up-not.v1",
            &message_id,
            TOPIC,
            Some(DESTINATION.to_string()),
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_PFORMAT)
                .map(|v| v.ce_integer()),
            Some(UPayloadFormat::Json.as_i32())
        );
        assert_eq!(event.text_data(), "{\"count\": 5}");
    }

    #[test]
    fn test_try_from_request_message_succeeds() {
        let payload = b"Hello";
        let message_id = UUID::build();
        let token = "my-token";
        let message = UMessageBuilder::request(
            UUri::from_str(METHOD).expect("failed to create sink URI"),
            UUri::from_str(REPLY_TO).expect("failed to create source URI"),
            TTL,
        )
        .with_message_id(message_id.clone())
        .with_priority(PRIORITY)
        .with_permission_level(PERMISSION_LEVEL)
        .with_traceparent(TRACEPARENT)
        .with_token(token)
        .build_with_payload(payload.as_slice(), UPayloadFormat::Raw)
        .expect("failed to create message");
        let event =
            CloudEvent::try_from(&message).expect("failed to create CloudEvent from UMessage");
        assert_standard_cloudevent_attributes(
            &event,
            "up-req.v1",
            &message_id,
            REPLY_TO,
            Some(METHOD.to_string()),
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_TOKEN)
                .map(|v| v.ce_string()),
            Some(token)
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_PERMISSION_LEVEL)
                .map(|v| v.ce_integer()),
            Some(PERMISSION_LEVEL as i32)
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_PFORMAT)
                .map(|v| v.ce_integer()),
            Some(UPayloadFormat::Raw.as_i32())
        );
        assert!(!event.has_proto_data());
        assert!(!event.has_text_data());
        assert_eq!(event.binary_data(), payload);
    }

    #[test]
    fn test_try_from_response_message_succeeds() {
        let mut payload = StringValue::new();
        payload.value = "Hello".into();

        let message_id = UUID::build();
        let request_id = UUID::build();

        let message = UMessageBuilder::response(
            UUri::from_str(REPLY_TO).expect("failed to create sink URI"),
            request_id.clone(),
            UUri::from_str(METHOD).expect("failed to create source URI"),
        )
        .with_message_id(message_id.clone())
        .with_ttl(TTL)
        .with_priority(PRIORITY)
        .with_comm_status(UCode::Ok)
        .with_traceparent(TRACEPARENT)
        .build_with_protobuf_payload(&payload)
        .expect("failed to create message");

        let event =
            CloudEvent::try_from(&message).expect("failed to create CloudEvent from UMessage");
        assert_standard_cloudevent_attributes(
            &event,
            "up-res.v1",
            &message_id,
            METHOD,
            Some(REPLY_TO.to_string()),
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_COMMSTATUS)
                .map(|v| v.ce_integer()),
            None
        );
        assert_eq!(
            event
                .attributes
                .get(EXTENSION_NAME_PFORMAT)
                .map(|v| v.ce_integer()),
            Some(UPayloadFormat::Protobuf.as_i32())
        );
        assert!(!event.has_binary_data());
        assert!(!event.has_text_data());
        assert_eq!(
            event.proto_data().value,
            Any::pack(&payload)
                .expect("failed to pack payload into Any")
                .value
        );
    }

    //
    // tests asserting conversion of CloudEvent -> UMessage
    // [utest->dsn~cloudevents-umessage-mapping~2]
    //

    fn assert_standard_umessage_attributes(
        attribs: &UAttributes,
        message_type: UMessageType,
        event_id: String,
        source: &str,
        sink: Option<String>,
    ) {
        assert_eq!(attribs.type_(), message_type);
        assert_eq!(attribs.id().to_hyphenated_string(), event_id);
        assert_eq!(attribs.source().to_uri(false), source);
        assert_eq!(attribs.sink().map(|uuri| uuri.to_uri(false)), sink);
        assert_eq!(attribs.priority_unchecked(), UPriority::CS4);
        assert_eq!(attribs.ttl(), Some(TTL));
        assert_eq!(attribs.traceparent(), Some(TRACEPARENT));
    }

    #[test]
    fn test_try_from_cloudevent_without_sink_fails() {
        let mut event = CloudEvent::new();
        event.spec_version = CLOUDEVENTS_SPEC_VERSION.into();
        event.type_ = UMessageType::Notification.to_cloudevent_type();
        event.id = UUID::build().to_hyphenated_string();
        event.source = TOPIC.into();

        assert!(UMessage::try_from(event).is_err());
    }

    #[test]
    fn test_try_from_publish_cloudevent_succeeds() {
        let event_id = UUID::build().to_hyphenated_string();
        let mut event = CloudEvent::new();
        event.spec_version = CLOUDEVENTS_SPEC_VERSION.into();
        event.type_ = UMessageType::Publish.to_cloudevent_type();
        event.id = event_id.clone();
        event.source = TOPIC.into();
        let mut injector = CloudEventInjector::new(event);
        injector
            .inject_priority(Some(UPriority::CS4))
            .expect("failed to set priority on message");
        injector
            .inject_ttl(Some(TTL))
            .expect("failed to set TTL on message");
        injector
            .inject_traceparent(Some(TRACEPARENT))
            .expect("failed to set traceparent on message");
        injector
            .inject_payload_format(Some(UPayloadFormat::Text))
            .expect("failed to set payload format on message");
        injector
            .inject_payload("test".as_bytes().into(), UPayloadFormat::Text)
            .expect("failed to set payload on message");
        let event = injector
            .finalize()
            .expect("failed to finalize CloudEventInjector");
        let umessage =
            UMessage::try_from(event).expect("failed to create UMessage from CloudEvent");
        let attribs = umessage.attributes();
        assert_standard_umessage_attributes(attribs, UMessageType::Publish, event_id, TOPIC, None);
        assert_eq!(attribs.payload_format_unchecked(), UPayloadFormat::Text);
        assert_eq!(umessage.payload(), Some("test".as_bytes().into()))
    }

    #[test]
    fn test_try_from_notification_cloudevent_succeeds() {
        let event_id = UUID::build().to_hyphenated_string();
        let mut event = CloudEvent::new();
        event.spec_version = CLOUDEVENTS_SPEC_VERSION.into();
        event.type_ = UMessageType::Notification.to_cloudevent_type();
        event.id = event_id.clone();
        event.source = TOPIC.into();

        let mut injector = CloudEventInjector::new(event);
        injector
            .inject_sink(Some(
                &UUri::try_from(DESTINATION).expect("failed to create sink URI"),
            ))
            .expect("failed to set sink on message");
        injector
            .inject_priority(Some(UPriority::CS4))
            .expect("failed to set priority on message");
        injector
            .inject_ttl(Some(TTL))
            .expect("failed to set TTL on message");
        injector
            .inject_traceparent(Some(TRACEPARENT))
            .expect("failed to set traceparent on message");
        injector
            .inject_payload_format(Some(UPayloadFormat::Json))
            .expect("failed to set payload format on message");
        injector
            .inject_payload("{\"count\": 5}".as_bytes().into(), UPayloadFormat::Json)
            .expect("failed to set payload on message");
        let event = injector
            .finalize()
            .expect("failed to finalize CloudEventInjector");
        let umessage =
            UMessage::try_from(event).expect("failed to create UMessage from CloudEvent");
        let attribs = umessage.attributes();
        assert_standard_umessage_attributes(
            attribs,
            UMessageType::Notification,
            event_id,
            TOPIC,
            Some(DESTINATION.to_string()),
        );
        assert_eq!(attribs.payload_format_unchecked(), UPayloadFormat::Json);
        assert_eq!(umessage.payload(), Some("{\"count\": 5}".as_bytes().into()))
    }

    #[test]
    fn test_try_from_request_cloudevent_succeeds() {
        let event_id = UUID::build().to_hyphenated_string();
        let mut event = CloudEvent::new();
        event.spec_version = CLOUDEVENTS_SPEC_VERSION.into();
        event.type_ = UMessageType::Request.to_cloudevent_type();
        event.id = event_id.clone();
        event.source = REPLY_TO.into();
        let mut injector = CloudEventInjector::new(event);
        injector
            .inject_sink(Some(
                &UUri::try_from(METHOD).expect("failed to create sink URI"),
            ))
            .expect("failed to set sink on message");
        injector
            .inject_priority(Some(UPriority::CS4))
            .expect("failed to set priority on message");
        injector
            .inject_ttl(Some(TTL))
            .expect("failed to set TTL on message");
        injector
            .inject_traceparent(Some(TRACEPARENT))
            .expect("failed to set traceparent on message");
        injector
            .inject_permission_level(Some(PERMISSION_LEVEL))
            .expect("failed to set permission level on message");
        injector
            .inject_token(Some("my-token"))
            .expect("failed to set token on message");

        let mut payload = StringValue::new();
        payload.value = "Hello".into();
        let payload_wrapped_in_any = Any::pack(&payload).expect("failed to wrap payload in Any");
        let serialized_payload: Bytes = payload_wrapped_in_any
            .write_to_bytes()
            .expect("failed to serialize payload")
            .into();
        injector
            .inject_payload_format(Some(UPayloadFormat::ProtobufWrappedInAny))
            .expect("failed to set payload format on message");
        injector
            .inject_payload(
                serialized_payload.clone(),
                UPayloadFormat::ProtobufWrappedInAny,
            )
            .expect("failed to set payload on message");
        let event = injector
            .finalize()
            .expect("failed to finalize CloudEventInjector");
        let umessage =
            UMessage::try_from(event).expect("failed to create UMessage from CloudEvent");
        let attribs = umessage.attributes();
        assert_standard_umessage_attributes(
            attribs,
            UMessageType::Request,
            event_id,
            REPLY_TO,
            Some(METHOD.to_string()),
        );
        assert_eq!(attribs.permission_level(), Some(PERMISSION_LEVEL));
        assert_eq!(attribs.token(), Some("my-token"));
        assert_eq!(
            attribs.payload_format_unchecked(),
            UPayloadFormat::ProtobufWrappedInAny
        );
        assert_eq!(umessage.payload(), Some(serialized_payload));
    }

    #[test]
    fn test_try_from_response_cloudevent_succeeds() {
        let event_id = UUID::build().to_hyphenated_string();
        let request_id = UUID::build();
        let mut event = CloudEvent::new();
        event.spec_version = CLOUDEVENTS_SPEC_VERSION.into();
        event.type_ = UMessageType::Response.to_cloudevent_type();
        event.id = event_id.clone();
        event.source = METHOD.into();

        let mut injector = CloudEventInjector::new(event);
        injector
            .inject_sink(Some(
                &UUri::try_from(REPLY_TO).expect("failed to create sink URI"),
            ))
            .expect("failed to inject sink");
        injector
            .inject_priority(Some(UPriority::CS4))
            .expect("failed to inject priority");
        injector
            .inject_ttl(Some(TTL))
            .expect("failed to inject TTL");
        injector
            .inject_traceparent(Some(TRACEPARENT))
            .expect("failed to inject traceparent");
        injector
            .inject_request_id(Some(&request_id))
            .expect("failed to inject request ID");
        injector
            .inject_commstatus(Some(UCode::Ok))
            .expect("failed to inject commstatus");

        injector
            .inject_payload_format(Some(UPayloadFormat::Protobuf))
            .expect("failed to set payload format on message");
        injector
            .inject_payload(DATA.as_slice().into(), UPayloadFormat::Protobuf)
            .expect("failed to inject payload");
        let event = injector
            .finalize()
            .expect("failed to finalize CloudEventInjector");
        let umessage =
            UMessage::try_from(event).expect("failed to create UMessage from CloudEvent");
        let attribs = umessage.attributes();
        assert_standard_umessage_attributes(
            attribs,
            UMessageType::Response,
            event_id,
            METHOD,
            Some(REPLY_TO.to_string()),
        );
        assert_eq!(attribs.commstatus(), None);
        assert_eq!(attribs.request_id(), Some(&request_id));
        assert_eq!(attribs.payload_format_unchecked(), UPayloadFormat::Protobuf);
        assert_eq!(umessage.payload(), Some(DATA.as_slice().into()));
    }
}
