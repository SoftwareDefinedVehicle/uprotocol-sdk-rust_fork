/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

/*!
The traits from this module can be implemented to extract the payload and attributes from a custom message format and inject them into a [`UMessage`] or vice versa. This allows for mapping between uProtocol messages and other message formats, such as CloudEvents or packet data units (PDU) of transport protocols like MQTT and Eclipse Zenoh.
*/

use bytes::Bytes;

use crate::{
    UAttributes, UAttributesError, UCode, UMessageType, UPayloadFormat, UPriority, UUri, UUID,
};

/// A strategy for extracting the payload from a custom message.
pub trait PayloadExtractor {
    fn extract_payload(&self) -> Result<Option<Bytes>, UAttributesError>;
}

/// A strategy for extracting uProtocol attributes _en bloc_ from a custom message.
pub trait UAttributesExtractor {
    fn extract_attributes(&self) -> Result<UAttributes, UAttributesError>;
}

/// A strategy for extracting uProtocol attributes individually from a custom message.
pub trait FieldExtractor {
    fn extract_id(&self) -> Result<UUID, UAttributesError>;
    fn extract_type(&self) -> Result<UMessageType, UAttributesError>;
    fn extract_source(&self) -> Result<UUri, UAttributesError>;
    fn extract_sink(&self) -> Result<Option<UUri>, UAttributesError>;
    fn extract_sink_required(&self) -> Result<UUri, UAttributesError>;
    fn extract_priority(&self) -> Result<Option<UPriority>, UAttributesError>;
    fn extract_ttl(&self) -> Result<Option<u32>, UAttributesError>;
    fn extract_token(&self) -> Result<Option<String>, UAttributesError>;
    fn extract_permission_level(&self) -> Result<Option<u32>, UAttributesError>;
    fn extract_request_id(&self) -> Result<Option<UUID>, UAttributesError>;
    fn extract_request_id_required(&self) -> Result<UUID, UAttributesError>;
    fn extract_commstatus(&self) -> Result<Option<UCode>, UAttributesError>;
    fn extract_traceparent(&self) -> Result<Option<String>, UAttributesError>;
    fn extract_payload_format(&self) -> Result<Option<UPayloadFormat>, UAttributesError>;
}

/// A strategy for injecting a uProtocol message's payload into a custom message.
///
/// # Arguments
/// * `payload` - The payload to inject into the custom message.
/// * `payload_format` - The format of the payload to inject into the custom message. This is
///   provided for reference here so that implementors can map the payload based on its type.
///   The payload format itself should be stored in the custom message as part of the
///   [FieldInjector::inject_payload_format] or [UAttributesInjector::inject_attributes] implementation.
///
/// # Errors
/// Returns an error if the payload or payload format cannot be injected into the custom message.
pub trait PayloadInjector {
    fn inject_payload(
        &mut self,
        payload: Bytes,
        payload_format: UPayloadFormat,
    ) -> Result<(), UAttributesError>;
}

/// A strategy for injecting uProtocol attributes _en bloc_ into a custom message.
pub trait UAttributesInjector {
    fn inject_attributes(&mut self, attributes: &UAttributes) -> Result<(), UAttributesError>;
}

/// A strategy for injecting uProtocol attributes individually into a custom message.
pub trait FieldInjector {
    fn inject_id(&mut self, id: &UUID) -> Result<(), UAttributesError>;
    fn inject_type(&mut self, type_: UMessageType) -> Result<(), UAttributesError>;
    fn inject_source(&mut self, uri: &UUri) -> Result<(), UAttributesError>;
    fn inject_sink(&mut self, uri: Option<&UUri>) -> Result<(), UAttributesError>;
    fn inject_priority(&mut self, priority: Option<UPriority>) -> Result<(), UAttributesError>;
    fn inject_ttl(&mut self, ttl: Option<u32>) -> Result<(), UAttributesError>;
    fn inject_permission_level(&mut self, level: Option<u32>) -> Result<(), UAttributesError>;
    fn inject_request_id(&mut self, id: Option<&UUID>) -> Result<(), UAttributesError>;
    fn inject_commstatus(&mut self, status: Option<UCode>) -> Result<(), UAttributesError>;
    fn inject_token(&mut self, token: Option<&str>) -> Result<(), UAttributesError>;
    fn inject_traceparent(&mut self, traceparent: Option<&str>) -> Result<(), UAttributesError>;
    fn inject_payload_format(
        &mut self,
        format: Option<UPayloadFormat>,
    ) -> Result<(), UAttributesError>;
}

/// A strategy for finalizing a custom message after all attributes and payload have been injected.
///
/// # Returns
/// Returns the custom message that contains all the uProtocol meta data and payload.
///
/// # Errors
/// Returns an error if the custom message cannot be created, for example if the payload or any of
/// the uProtocol message meta data cannot be mapped to the custom message.
pub trait MessageFinalizer {
    type Target;

    fn finalize(self) -> Result<Self::Target, UAttributesError>;
}
