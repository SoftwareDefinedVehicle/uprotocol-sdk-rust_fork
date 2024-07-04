/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
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

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use protobuf::Message;
use tracing::debug;

use crate::{
    LocalUriProvider, UAttributes, UAttributesError, UAttributesValidators, UCode, UListener,
    UMessage, UMessageBuilder, UMessageType, UPayloadFormat, UPriority, UStatus, UTransport, UUri,
};

use super::{RegistrationError, RequestHandler, RpcServer, ServiceInvocationError, UPayload};

struct RequestListener {
    request_handler: Arc<dyn RequestHandler>,
    transport: Arc<dyn UTransport>,
}

impl RequestListener {
    async fn process_valid_request(&self, request_message: UMessage) {
        let Some(resource_id) = request_message
            .attributes
            .as_ref()
            .and_then(|attribs| attribs.sink.as_ref())
            .and_then(|uri| u16::try_from(uri.resource_id).ok())
        else {
            // the conversion cannot fail because the UListener has already verified that the
            // request message is indeed a valid uProtocol RPC Request with a proper sink
            // URI representing a method (having a 16 bit resource ID).
            return;
        };

        let transport_clone = self.transport.clone();
        let request_handler_clone = self.request_handler.clone();

        let request_id = request_message
            .attributes
            .get_or_default()
            .id
            .get_or_default();
        let request_timeout = request_message
            .attributes
            .get_or_default()
            .ttl
            .unwrap_or(10_000);
        let payload = request_message.payload;
        let payload_format = request_message
            .attributes
            .get_or_default()
            .payload_format
            .enum_value_or_default();
        let request_payload = payload.map(|data| UPayload::new(data, payload_format));

        debug!(ttl = request_timeout, id = %request_id, "processing RPC request");

        let invocation_result_future =
            request_handler_clone.invoke_method(resource_id, request_payload);
        let outcome = tokio::time::timeout(
            Duration::from_millis(request_timeout as u64),
            invocation_result_future,
        )
        .await
        .map_err(|_e| {
            debug!(ttl = request_timeout, "request handler timed out");
            ServiceInvocationError::DeadlineExceeded
        })
        .and_then(|v| v);

        let response = match outcome {
            Ok(response_payload) => {
                let mut builder = UMessageBuilder::response_for_request(
                    request_message.attributes.get_or_default(),
                );
                if let Some(payload) = response_payload {
                    let format = payload.payload_format();
                    builder.build_with_payload(payload.payload(), format)
                } else {
                    builder.build()
                }
            }
            Err(e) => {
                let error = UStatus::from(e);
                UMessageBuilder::response_for_request(request_message.attributes.get_or_default())
                    .with_comm_status(error.get_code())
                    .build_with_protobuf_payload(&error)
            }
        };

        match response {
            Ok(response_message) => {
                if let Err(e) = transport_clone.send(response_message).await {
                    debug!(ucode = e.code.value(), "failed to send response message");
                }
            }
            Err(e) => {
                debug!("failed to create response message: {}", e);
            }
        }
    }

    async fn process_invalid_request(&self, validation_error: UAttributesError, msg: UMessage) {
        // all we need is a valid source address and a message ID to be able to send back an error message
        let (Some(id), Some(source_address)) = (
            msg.attributes.get_or_default().id.to_owned().into_option(),
            msg.attributes
                .get_or_default()
                .source
                .to_owned()
                .into_option()
                .filter(|uri| uri.is_rpc_response()),
        ) else {
            debug!("invalid request message does not contain enough data to create response");
            return;
        };

        debug!(id = %id, "processing invalid request message");

        let response_payload =
            UStatus::fail_with_code(UCode::INVALID_ARGUMENT, validation_error.to_string());
        let response_attributes = UAttributes {
            type_: UMessageType::UMESSAGE_TYPE_RESPONSE.into(),
            id: Some(crate::UUID::build()).into(),
            reqid: Some(id).into(),
            commstatus: Some(response_payload.get_code().into()),
            sink: Some(source_address).into(),
            source: msg.attributes.get_or_default().sink.clone(),
            priority: UPriority::UPRIORITY_CS4.into(),
            payload_format: UPayloadFormat::UPAYLOAD_FORMAT_PROTOBUF.into(),
            ..Default::default()
        };

        let Ok(response_message) = response_payload.write_to_bytes().map(|buf| UMessage {
            attributes: Some(response_attributes).into(),
            payload: Some(buf.into()),
            ..Default::default()
        }) else {
            debug!("failed to create error message");
            return;
        };

        if let Err(e) = self.transport.send(response_message).await {
            debug!(ucode = e.code.value(), "failed to send error response");
        }
    }
}

#[async_trait]
impl UListener for RequestListener {
    async fn on_receive(&self, msg: UMessage) {
        let Some(attributes) = msg.attributes.as_ref() else {
            debug!("ignoring invalid message having no attributes");
            return;
        };

        let validator = UAttributesValidators::Request.validator();
        if let Err(e) = validator.validate(attributes) {
            self.process_invalid_request(e, msg).await;
        } else {
            self.process_valid_request(msg).await;
        }
    }
}

pub struct InMemoryRpcServer {
    transport: Arc<dyn UTransport>,
    uri_provider: Arc<dyn LocalUriProvider>,
    request_listeners: tokio::sync::Mutex<HashMap<u16, Arc<dyn UListener>>>,
}

impl InMemoryRpcServer {
    /// Creates a new RPC server for a given transport.
    pub fn new(transport: Arc<dyn UTransport>, uri_provider: Arc<dyn LocalUriProvider>) -> Self {
        InMemoryRpcServer {
            transport,
            uri_provider,
            request_listeners: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    fn validate_sink_filter(filter: &UUri) -> Result<(), RegistrationError> {
        if !filter.is_rpc_method() {
            return Err(RegistrationError::InvalidFilter(
                "RPC endpoint's resource ID must be in range [0x0001, 0x7FFF]".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_origin_filter(filter: Option<&UUri>) -> Result<(), RegistrationError> {
        if let Some(uri) = filter {
            if !uri.is_rpc_response() {
                return Err(RegistrationError::InvalidFilter(
                    "origin filter's resource ID must be 0".to_string(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    async fn contains_endpoint(&self, resource_id: u16) -> bool {
        let listener_map = self.request_listeners.lock().await;
        listener_map.contains_key(&resource_id)
    }
}

#[async_trait]
impl RpcServer for InMemoryRpcServer {
    async fn register_endpoint(
        &self,
        origin_filter: Option<&UUri>,
        resource_id: u16,
        request_handler: Arc<dyn RequestHandler>,
    ) -> Result<(), RegistrationError> {
        Self::validate_origin_filter(origin_filter)?;
        let sink_filter = self.uri_provider.get_resource_uri(resource_id);
        Self::validate_sink_filter(&sink_filter)?;

        let mut listener_map = self.request_listeners.lock().await;
        if let Entry::Vacant(e) = listener_map.entry(resource_id) {
            let listener = Arc::new(RequestListener {
                request_handler,
                transport: self.transport.clone(),
            });
            self.transport
                .register_listener(
                    origin_filter.unwrap_or(&UUri::any()),
                    Some(&sink_filter),
                    listener.clone(),
                )
                .await
                .map(|_| {
                    e.insert(listener);
                })
                .map_err(RegistrationError::from)
        } else {
            Err(RegistrationError::MaxListenersExceeded)
        }
    }

    async fn unregister_endpoint(
        &self,
        origin_filter: Option<&UUri>,
        resource_id: u16,
        _request_handler: Arc<dyn RequestHandler>,
    ) -> Result<(), RegistrationError> {
        Self::validate_origin_filter(origin_filter)?;
        let sink_filter = self.uri_provider.get_resource_uri(resource_id);
        Self::validate_sink_filter(&sink_filter)?;

        let mut listener_map = self.request_listeners.lock().await;
        if let Entry::Occupied(entry) = listener_map.entry(resource_id) {
            let listener = entry.get().to_owned();
            self.transport
                .unregister_listener(
                    origin_filter.unwrap_or(&UUri::any()),
                    Some(&sink_filter),
                    listener,
                )
                .await
                .map(|_| {
                    entry.remove();
                })
                .map_err(RegistrationError::from)
        } else {
            Err(RegistrationError::NoSuchListener)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use mockall::mock;
    use protobuf::well_known_types::wrappers::StringValue;
    use test_case::test_case;
    use tokio::sync::Notify;

    use crate::{UAttributes, UMessageType, UPriority, UUri, UUID};

    mock! {
        pub Handler {}
        #[async_trait]
        impl RequestHandler for Handler {
            async fn invoke_method(
                &self,
                resource_id: u16,
                request_payload: Option<UPayload>,
            ) -> Result<Option<UPayload>, ServiceInvocationError>;
        }
    }

    mock! {
        pub UriProvider {}
        impl LocalUriProvider for UriProvider {
            fn get_authority(&self) -> String;
            fn get_resource_uri(&self, resource_id: u16) -> UUri;
            fn get_source_uri(&self) -> UUri;
        }
    }

    mock! {
        pub Transport {
            async fn do_send(&self, message: UMessage) -> Result<(), UStatus>;
            async fn do_register_listener<'a>(&'a self, source_filter: &'a UUri, sink_filter: Option<&'a UUri>, listener: Arc<dyn UListener>) -> Result<(), UStatus>;
            async fn do_unregister_listener<'a>(&'a self, source_filter: &'a UUri, sink_filter: Option<&'a UUri>, listener: Arc<dyn UListener>) -> Result<(), UStatus>;
        }
    }

    #[async_trait]
    impl UTransport for MockTransport {
        async fn send(&self, message: UMessage) -> Result<(), UStatus> {
            self.do_send(message).await
        }
        async fn register_listener(
            &self,
            source_filter: &UUri,
            sink_filter: Option<&UUri>,
            listener: Arc<dyn UListener>,
        ) -> Result<(), UStatus> {
            self.do_register_listener(source_filter, sink_filter, listener)
                .await
        }
        async fn unregister_listener(
            &self,
            source_filter: &UUri,
            sink_filter: Option<&UUri>,
            listener: Arc<dyn UListener>,
        ) -> Result<(), UStatus> {
            self.do_unregister_listener(source_filter, sink_filter, listener)
                .await
        }
    }

    fn new_uri_provider() -> Arc<dyn LocalUriProvider> {
        let mut mock_uri_provider = MockUriProvider::new();
        mock_uri_provider
            .expect_get_resource_uri()
            .returning(|resource_id| UUri {
                ue_id: 0x0005,
                ue_version_major: 0x02,
                resource_id: resource_id as u32,
                ..Default::default()
            });
        Arc::new(mock_uri_provider)
    }

    #[test_case(None, 0x4A10; "for empty origin filter")]
    #[test_case(Some(UUri::from_parts("authority", 0xBF1A, 0x01, 0x0000)), 0x4A10; "for specific origin filter")]
    #[test_case(Some(UUri::from_parts("*", 0xFFFF, 0x01, 0x0000)), 0x7091; "for wildcard origin filter")]
    #[tokio::test]
    async fn test_register_endpoint_succeeds(origin_filter: Option<UUri>, resource_id: u16) {
        // GIVEN an RpcServer for a transport
        let request_handler = Arc::new(MockHandler::new());
        let mut transport = MockTransport::new();
        let uri_provider = new_uri_provider();
        let expected_source_filter = origin_filter.clone().unwrap_or(UUri::any());
        let param_check = move |source_filter: &UUri,
                                sink_filter: &Option<&UUri>,
                                _listener: &Arc<dyn UListener>| {
            source_filter == &expected_source_filter
                && sink_filter.map_or(false, |uri| uri.resource_id == resource_id as u32)
        };
        transport
            .expect_do_register_listener()
            .once()
            .withf(param_check.clone())
            .returning(|_source_filter, _sink_filter, _listener| Ok(()));
        transport
            .expect_do_unregister_listener()
            .once()
            .withf(param_check)
            .returning(|_source_filter, _sink_filter, _listener| Ok(()));

        let rpc_server = InMemoryRpcServer::new(Arc::new(transport), uri_provider);

        // WHEN registering a request handler
        let register_result = rpc_server
            .register_endpoint(origin_filter.as_ref(), resource_id, request_handler.clone())
            .await;
        // THEN registration succeeds
        assert!(register_result.is_ok());
        assert!(rpc_server.contains_endpoint(resource_id).await);

        // and the handler can be unregistered again
        let unregister_result = rpc_server
            .unregister_endpoint(origin_filter.as_ref(), resource_id, request_handler)
            .await;
        assert!(unregister_result.is_ok());
        assert!(!rpc_server.contains_endpoint(resource_id).await);
    }

    #[test_case(None, 0x0000; "for resource ID 0")]
    #[test_case(None, 0x8000; "for resource ID out of range")]
    #[test_case(Some(UUri::from_parts("*", 0xFFFF, 0xFF, 0x0001)), 0x4A10; "for source filter with invalid resource ID")]
    #[tokio::test]
    async fn test_register_endpoint_fails(origin_filter: Option<UUri>, resource_id: u16) {
        // GIVEN an RpcServer for a transport
        let request_handler = Arc::new(MockHandler::new());
        let mut transport = MockTransport::new();
        let uri_provider = new_uri_provider();
        transport.expect_do_register_listener().never();
        transport.expect_do_unregister_listener().never();

        let rpc_server = InMemoryRpcServer::new(Arc::new(transport), uri_provider);

        // WHEN registering a request handler using invalid parameters
        let register_result = rpc_server
            .register_endpoint(origin_filter.as_ref(), resource_id, request_handler.clone())
            .await;
        // THEN registration fails
        assert!(register_result.is_err_and(|e| matches!(e, RegistrationError::InvalidFilter(_v))));
        assert!(!rpc_server.contains_endpoint(resource_id).await);

        // and an attempt to unregister the handler using the same invalid parameters also fails with the same error
        let unregister_result = rpc_server
            .unregister_endpoint(origin_filter.as_ref(), resource_id, request_handler)
            .await;
        assert!(unregister_result.is_err_and(|e| matches!(e, RegistrationError::InvalidFilter(_v))));
    }

    #[tokio::test]
    async fn test_register_endpoint_fails_for_duplicate_endpoint() {
        // GIVEN an RpcServer for a transport
        let request_handler = Arc::new(MockHandler::new());
        let mut transport = MockTransport::new();
        let uri_provider = new_uri_provider();
        transport
            .expect_do_register_listener()
            .once()
            .return_const(Ok(()));

        let rpc_server = InMemoryRpcServer::new(Arc::new(transport), uri_provider);

        // WHEN registering a request handler for an already existing endpoint
        assert!(rpc_server
            .register_endpoint(None, 0x5000, request_handler.clone())
            .await
            .is_ok());
        let result = rpc_server
            .register_endpoint(None, 0x5000, request_handler)
            .await;

        // THEN registration of the additional handler fails
        assert!(result.is_err_and(|e| matches!(e, RegistrationError::MaxListenersExceeded)));
        // but the original endpoint is still registered
        assert!(rpc_server.contains_endpoint(0x5000).await);
    }

    #[tokio::test]
    async fn test_unregister_endpoint_fails_for_non_existing_endpoint() {
        // GIVEN an RpcServer for a transport
        let request_handler = Arc::new(MockHandler::new());
        let mut transport = MockTransport::new();
        let uri_provider = new_uri_provider();
        transport.expect_do_unregister_listener().never();

        let rpc_server = InMemoryRpcServer::new(Arc::new(transport), uri_provider);

        // WHEN trying to unregister a non existing endpoint
        assert!(!rpc_server.contains_endpoint(0x5000).await);
        let result = rpc_server
            .unregister_endpoint(None, 0x5000, request_handler)
            .await;

        // THEN registration fails
        assert!(result.is_err_and(|e| matches!(e, RegistrationError::NoSuchListener)));
    }

    #[tokio::test]
    async fn test_request_listener_returns_response_for_invalid_request() {
        // GIVEN an RpcServer for a transport
        let mut request_handler = MockHandler::new();
        let mut transport = MockTransport::new();
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let message_id = UUID::build();
        let request_id = message_id.clone();

        request_handler.expect_invoke_method().never();
        transport
            .expect_do_send()
            .once()
            .withf(move |response_message| {
                if !response_message.is_response() {
                    return false;
                }
                if response_message
                    .attributes
                    .get_or_default()
                    .reqid
                    .get_or_default()
                    != &request_id
                {
                    return false;
                }
                let error: UStatus = response_message.extract_protobuf().unwrap();
                error.get_code() == UCode::INVALID_ARGUMENT
                    && response_message
                        .attributes
                        .get_or_default()
                        .commstatus
                        .map_or(false, |v| v.enum_value_or_default() == error.get_code())
            })
            .returning(move |_msg| {
                notify_clone.notify_one();
                Ok(())
            });

        // WHEN the server receives a message on an endpoint which is not a
        // valid RPC Request message but contains enough information to
        // create a response
        let invalid_request_attributes = UAttributes {
            type_: UMessageType::UMESSAGE_TYPE_REQUEST.into(),
            sink: UUri::try_from("up://localhost/A200/1/7000").ok().into(),
            source: UUri::try_from("up://localhost/A100/1/0").ok().into(),
            id: Some(message_id.clone()).into(),
            priority: UPriority::UPRIORITY_CS5.into(),
            ..Default::default()
        };
        assert!(
            UAttributesValidators::Request
                .validator()
                .validate(&invalid_request_attributes)
                .is_err(),
            "request message attributes are supposed to be invalid (no TTL)"
        );
        let invalid_request_message = UMessage {
            attributes: Some(invalid_request_attributes).into(),
            ..Default::default()
        };

        let request_listener = RequestListener {
            request_handler: Arc::new(request_handler),
            transport: Arc::new(transport),
        };
        request_listener.on_receive(invalid_request_message).await;

        // THEN the listener sends an error message in response to the invalid request
        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_listener_ignores_invalid_request() {
        // GIVEN an RpcServer for a transport
        let mut request_handler = MockHandler::new();
        request_handler.expect_invoke_method().never();
        let mut transport = MockTransport::new();
        transport.expect_do_send().never();

        // WHEN the server receives a message on an endpoint which is not a
        // valid RPC Request message which does not contain enough information to
        // create a response
        let invalid_request_attributes = UAttributes {
            type_: UMessageType::UMESSAGE_TYPE_REQUEST.into(),
            sink: UUri::try_from("up://localhost/A200/1/7000").ok().into(),
            source: UUri::try_from("up://localhost/A100/1/0").ok().into(),
            ttl: Some(5_000),
            id: None.into(),
            priority: UPriority::UPRIORITY_CS5.into(),
            ..Default::default()
        };
        assert!(
            UAttributesValidators::Request
                .validator()
                .validate(&invalid_request_attributes)
                .is_err(),
            "request message attributes are supposed to be invalid (no ID)"
        );
        let invalid_request_message = UMessage {
            attributes: Some(invalid_request_attributes).into(),
            ..Default::default()
        };

        let request_listener = RequestListener {
            request_handler: Arc::new(request_handler),
            transport: Arc::new(transport),
        };
        request_listener.on_receive(invalid_request_message).await;

        // THEN the listener ignores the invalid request
        // let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        // assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_listener_invokes_operation_successfully() {
        let mut request_handler = MockHandler::new();
        let mut transport = MockTransport::new();
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let request_payload = StringValue {
            value: "Hello".to_string(),
            ..Default::default()
        };
        let message_id = UUID::build();
        let message_id_clone = message_id.clone();

        request_handler
            .expect_invoke_method()
            .once()
            .withf(|resource_id, request_payload| {
                if let Some(pl) = request_payload {
                    let msg: StringValue = pl.extract_protobuf().unwrap();
                    msg.value == *"Hello" && *resource_id == 0x7000_u16
                } else {
                    false
                }
            })
            .returning(|_resource_id, _request_payload| {
                let response_payload = UPayload::try_from_protobuf(StringValue {
                    value: "Hello World".to_string(),
                    ..Default::default()
                })
                .unwrap();
                Ok(Some(response_payload))
            });
        transport
            .expect_do_send()
            .once()
            .withf(move |response_message| {
                let msg: StringValue = response_message.extract_protobuf().unwrap();
                msg.value == *"Hello World"
                    && response_message.is_response()
                    && response_message
                        .attributes
                        .get_or_default()
                        .commstatus
                        .map_or(true, |v| v.enum_value_or_default() == UCode::OK)
                    && response_message
                        .attributes
                        .get_or_default()
                        .reqid
                        .get_or_default()
                        == &message_id_clone
            })
            .returning(move |_msg| {
                notify_clone.notify_one();
                Ok(())
            });
        let request_message = UMessageBuilder::request(
            UUri::try_from("up://localhost/A200/1/7000").unwrap(),
            UUri::try_from("up://localhost/A100/1/0").unwrap(),
            5_000,
        )
        .with_message_id(message_id)
        .build_with_protobuf_payload(&request_payload)
        .unwrap();

        let request_listener = RequestListener {
            request_handler: Arc::new(request_handler),
            transport: Arc::new(transport),
        };
        request_listener.on_receive(request_message).await;
        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_listener_invokes_operation_erroneously() {
        let mut request_handler = MockHandler::new();
        let mut transport = MockTransport::new();
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let message_id = UUID::build();
        let message_id_clone = message_id.clone();

        request_handler
            .expect_invoke_method()
            .once()
            .withf(|resource_id, _request_payload| *resource_id == 0x7000_u16)
            .returning(|_resource_id, _request_payload| {
                Err(ServiceInvocationError::NotFound(
                    "no such object".to_string(),
                ))
            });
        transport
            .expect_do_send()
            .once()
            .withf(move |response_message| {
                let error: UStatus = response_message.extract_protobuf().unwrap();
                error.get_code() == UCode::NOT_FOUND
                    && response_message.is_response()
                    && response_message
                        .attributes
                        .get_or_default()
                        .commstatus
                        .map_or(false, |v| v.enum_value_or_default() == error.get_code())
                    && response_message
                        .attributes
                        .get_or_default()
                        .reqid
                        .get_or_default()
                        == &message_id_clone
            })
            .returning(move |_msg| {
                notify_clone.notify_one();
                Ok(())
            });
        let request_message = UMessageBuilder::request(
            UUri::try_from("up://localhost/A200/1/7000").unwrap(),
            UUri::try_from("up://localhost/A100/1/0").unwrap(),
            5_000,
        )
        .with_message_id(message_id)
        .build()
        .unwrap();

        let request_listener = RequestListener {
            request_handler: Arc::new(request_handler),
            transport: Arc::new(transport),
        };
        request_listener.on_receive(request_message).await;
        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_listener_times_out() {
        // we need to manually implement the RequestHandler
        // because from within the MockRequestHandler's expectation
        // we cannot yield the current task (we can only use the blocking
        // thread::sleep function)
        struct NonRespondingHandler;
        #[async_trait]
        impl RequestHandler for NonRespondingHandler {
            async fn invoke_method(
                &self,
                resource_id: u16,
                _request_payload: Option<UPayload>,
            ) -> Result<Option<UPayload>, ServiceInvocationError> {
                assert_eq!(resource_id, 0x7000);
                // this will yield the current task and allow the
                // RequestListener to run into the timeout
                tokio::time::sleep(Duration::from_millis(2000)).await;
                Ok(None)
            }
        }

        let request_handler = NonRespondingHandler {};
        let mut transport = MockTransport::new();
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let message_id = UUID::build();
        let message_id_clone = message_id.clone();

        transport
            .expect_do_send()
            .once()
            .withf(move |response_message| {
                let error: UStatus = response_message.extract_protobuf().unwrap();
                error.get_code() == UCode::DEADLINE_EXCEEDED
                    && response_message.is_response()
                    && response_message
                        .attributes
                        .get_or_default()
                        .commstatus
                        .map_or(false, |v| v.enum_value_or_default() == error.get_code())
                    && response_message
                        .attributes
                        .get_or_default()
                        .reqid
                        .get_or_default()
                        == &message_id_clone
            })
            .returning(move |_msg| {
                notify_clone.notify_one();
                Ok(())
            });
        let request_message = UMessageBuilder::request(
            UUri::try_from("up://localhost/A200/1/7000").unwrap(),
            UUri::try_from("up://localhost/A100/1/0").unwrap(),
            // make sure this request times out very quickly
            100,
        )
        .with_message_id(message_id)
        .build()
        .expect("should have been able to create RPC Request message");

        let request_listener = RequestListener {
            request_handler: Arc::new(request_handler),
            transport: Arc::new(transport),
        };
        request_listener.on_receive(request_message).await;
        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok());
    }
}
