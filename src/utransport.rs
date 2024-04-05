/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
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

use async_trait::async_trait;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

use crate::{UMessage, UStatus, UUri};

/// `UListener` is the uP-L1 interface that provides a means to create listeners which are registered to [`UTransport`]
///
/// Implementations of `UListener` contain the details for what should occur when a message is received
///
/// For more information, please refer to
/// [uProtocol Specification](https://github.com/eclipse-uprotocol/uprotocol-spec/blob/main/up-l1/README.adoc).
///
/// # Examples
///
/// ## Simple example
///
/// ```
/// use up_rust::{UListener, UMessage, UStatus};
///
/// use async_trait::async_trait;
/// use std::sync::{Arc, Mutex};
///
/// #[derive(Clone)]
/// struct FooListener {
///     inner_foo: Arc<Mutex<String>>
/// }
///
/// #[async_trait]
/// impl UListener for FooListener {
///     async fn on_receive(&self, msg: UMessage) {
///         let mut inner_foo = self.inner_foo.lock().unwrap();
///         if let Some(payload) = msg.payload.as_ref() {
///             if let Some(length) = payload.length.as_ref() {
///                 *inner_foo = format!("latest message length: {length}");
///             }
///         }
///     }
///
///     async fn on_error(&self, err: UStatus) {
///         println!("uh oh, we got an error: {err:?}");
///     }
/// }
/// ```
///
/// ## Long-running function needed when message received
///
/// ```
/// use up_rust::{UListener, UMessage, UStatus};
///
/// use async_trait::async_trait;
/// use async_std::task;
/// use std::sync::{Arc, Mutex};
///
/// #[derive(Clone)]
/// struct LongTaskListener;
///
/// async fn send_to_jupiter(message_for_jupiter: UMessage) {
///     // send a message to Jupiter
///     println!("Fly me to the moon... {message_for_jupiter}");
/// }
///
/// #[async_trait]
/// impl UListener for LongTaskListener {
///     async fn on_receive(&self, msg: UMessage) {
///         task::spawn(send_to_jupiter(msg));
///     }
///
///     async fn on_error(&self, err: UStatus) {
///         println!("unable to send to jupiter :( {err:?}");
///     }
/// }
/// ```
#[async_trait]
pub trait UListener: Send + Sync {
    /// Performs some action on receipt of a message
    ///
    /// # Parameters
    ///
    /// * `msg` - The message
    ///
    /// # Note for `UListener` implementers
    ///
    /// `on_receive()` is expected to return almost immediately. If it does not, it could potentially
    /// block further message receipt. For long-running operations consider passing off received
    /// data to a different async function to handle it and returning.
    ///
    /// # Note for `UTransport` implementers
    ///
    /// Because `on_receive()` is async you may choose to either `.await` it in the current context
    /// or spawn it onto a new task and await there to allow current context to immediately continue.
    async fn on_receive(&self, msg: UMessage);

    /// Performs some action on receipt of an error
    ///
    /// # Parameters
    ///
    /// * `err` - The error as `UStatus`
    ///
    /// # Note for `UListener` implementers
    ///
    /// `on_error()` is expected to return almost immediately. If it does not, it could potentially
    /// block further message receipt. For long-running operations consider passing off received
    /// error to a different async function to handle it and returning.
    ///
    /// # Note for `UTransport` implementers
    ///
    /// Because `on_error()` is async you may choose to either `.await` it in the current context
    /// or spawn it onto a new task and await there to allow current context to immediately continue.
    async fn on_error(&self, err: UStatus);
}

/// [`UTransport`] is the uP-L1 interface that provides a common API for uE developers to send and receive messages.
///
/// Implementations of [`UTransport`] contain the details for connecting to the underlying transport technology and
/// sending [`UMessage`][crate::UMessage] using the configured technology. For more information, please refer to
/// [uProtocol Specification](https://github.com/eclipse-uprotocol/uprotocol-spec/blob/main/up-l1/README.adoc).
#[async_trait]
pub trait UTransport: Send + Sync {
    /// Sends a message using this transport's message exchange mechanism.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to send. The `type`, `source` and`sink` properties of the [`crate::UAttributes`] contained
    ///   in the message determine the addressing semantics:
    ///   * `source` - The origin of the message being sent. The address must be resolved. The semantics of the address
    ///     depends on the value of the given [attributes' type](crate::UAttributes::type_) property .
    ///     * For a [`PUBLISH`](crate::UMessageType::UMESSAGE_TYPE_PUBLISH) message, this is the topic that the message should be published to,
    ///     * for a [`REQUEST`](crate::UMessageType::UMESSAGE_TYPE_REQUEST) message, this is the *reply-to* address that the sender expects to receive the response at, and
    ///     * for a [`RESPONSE`](crate::UMessageType::UMESSAGE_TYPE_RESPONSE) message, this identifies the method that has been invoked.
    ///   * `sink` - For a `notification`, an RPC `request` or RPC `response` message, the (resolved) address that the message
    ///     should be sent to.
    ///
    /// # Errors
    ///
    /// Returns an error if the message could not be sent.
    async fn send(&self, message: UMessage) -> Result<(), UStatus>;

    /// Receives a message from the transport.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic to receive the message from.
    ///
    /// # Errors
    ///
    /// Returns an error if no message could be received. Possible reasons are that the topic does not exist
    /// or that no message is available from the topic.
    async fn receive(&self, topic: UUri) -> Result<UMessage, UStatus>;

    /// Registers a listener to be called for each message that is received on a given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The (resolved) address to register the listener for.
    /// * `listener` - The listener to invoke. Note that we do not take ownership to communicate
    ///                that a caller should keep a copy to be able to call `unregister_listener()`
    ///
    /// # Errors
    ///
    /// Returns an error if the listener could not be registered.
    ///
    /// # Examples
    ///
    /// ## Registering a listener
    ///
    /// ```
    /// use std::sync::Arc;
    /// use up_rust::UListener;
    /// # use up_rust::{UMessage, UStatus, UTransport, UUri};
    /// # use async_trait::async_trait;
    /// #
    /// # pub struct MyTransport;
    /// #
    /// # impl MyTransport {
    /// #     pub fn new()->Self {
    /// #         Self
    /// #     }
    /// # }
    /// #
    /// # #[async_trait]
    /// # impl UTransport for MyTransport {
    /// #     async fn send(&self, _message: UMessage) -> Result<(), UStatus> {
    /// #         todo!()
    /// #     }
    /// #
    /// #     async fn receive(&self, _topic: UUri) -> Result<UMessage, UStatus> {
    /// #         todo!()
    /// #     }
    /// #
    /// #     async fn register_listener(&self, _topic: UUri, _listener: Arc<dyn UListener>) -> Result<(), UStatus> {
    /// #         Ok(())
    /// #     }
    /// #
    /// #     async fn unregister_listener(&self, _topic: UUri, _listener: Arc<dyn UListener>) -> Result<(), UStatus> {
    /// #         Ok(())
    /// #     }
    /// # }
    /// #
    /// # #[derive(Clone)]
    /// # pub struct MyListener;
    /// #
    /// # impl MyListener {
    /// #     pub fn new() -> Self {
    /// #         Self
    /// #     }
    /// # }
    /// #
    /// # #[async_trait]
    /// # impl UListener for MyListener {
    /// #     async fn on_receive(&self, msg: UMessage) {
    /// #         todo!()
    /// #     }
    /// #
    /// #     async fn on_error(&self, err: UStatus) {
    /// #         todo!()
    /// #     }
    /// # }
    /// #
    /// # let my_transport = MyTransport::new();
    /// # let my_uuri = UUri::default();
    ///
    /// // hang onto this listener...
    /// let my_listener: Arc<dyn UListener> = Arc::new(MyListener::new());
    /// // ...send a clone through when registering...
    /// let register_result = my_transport.register_listener(my_uuri.clone(), my_listener.clone());
    /// // ...and use the original we hung onto when unregistering
    /// let unregister_result = my_transport.unregister_listener(my_uuri, my_listener);
    /// ```
    async fn register_listener(
        &self,
        topic: UUri,
        listener: Arc<dyn UListener>,
    ) -> Result<(), UStatus>;

    /// Unregisters a listener for a given topic.
    ///
    /// Messages arriving on this topic will no longer be processed by this listener.
    ///
    /// # Arguments
    ///
    /// * `topic` - Resolved topic uri where the listener was registered originally.
    /// * `listener` - Identifier of the listener that should be unregistered. Here we take ownership
    ///                to communicate that this listener is now finished.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener could not be unregistered, for example if the given listener does not exist.
    async fn unregister_listener(
        &self,
        topic: UUri,
        listener: Arc<dyn UListener>,
    ) -> Result<(), UStatus>;
}

/// A wrapper type around UListener that can be used by `up-client-foo-rust` UPClient libraries
/// to ease some common development scenarios when we want to compare [`UListener`][crate::UListener]
///
/// # Note
///
/// Not necessary for end-user uEs to use. Primarily intended for `up-client-foo-rust` UPClient libraries
/// when implementing [`UTransport`]
///
/// # Rationale
///
/// The wrapper type is implemented such that it can be used in any location you may wish to
/// hold a type implementing [`UListener`][crate::UListener]
///
/// Implements necessary traits to allow hashing, so that you may hold the wrapper type in
/// collections which require that, such as a `HashMap` or `HashSet`
#[derive(Clone)]
pub struct ComparableListener {
    listener: Arc<dyn UListener>,
}

impl ComparableListener {
    pub fn new(listener: Arc<dyn UListener>) -> Self {
        Self { listener }
    }
}

/// Allows us to call the methods on the held `Arc<dyn UListener>` directly
impl Deref for ComparableListener {
    type Target = dyn UListener;

    fn deref(&self) -> &Self::Target {
        &*self.listener
    }
}

/// The `Hash` implementation uses the held `Arc` pointer so that the same hash should result only
/// in the case that two [`ComparableListener`] were constructed with the same `Arc<T>` where `T`
/// implements [`UListener`][crate::UListener]
impl Hash for ComparableListener {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.listener).hash(state);
    }
}

/// Uses pointer equality to ensure that two [`ComparableListener`] are equal only if they were
/// constructed with the same `Arc<T>` where `T` implements [`UListener`][crate::UListener]
impl PartialEq for ComparableListener {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.listener, &other.listener)
    }
}

impl Eq for ComparableListener {}

#[cfg(test)]
mod tests {
    use crate::ComparableListener;
    use crate::UListener;
    use crate::{Number, UAuthority, UCode, UMessage, UStatus, UTransport, UUri};
    use async_std::task;
    use async_trait::async_trait;
    use std::collections::hash_map::Entry;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    struct UPClientFoo {
        #[allow(clippy::type_complexity)]
        listeners: Arc<Mutex<HashMap<UUri, HashSet<ComparableListener>>>>,
    }

    impl UPClientFoo {
        pub fn new() -> Self {
            Self {
                listeners: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        pub fn check_on_receive(&self, uuri: &UUri, umessage: &UMessage) -> Result<(), UStatus> {
            let mut topics_listeners = self.listeners.lock().unwrap();
            let listeners = topics_listeners.entry(uuri.clone());
            match listeners {
                Entry::Vacant(_) => {
                    return Err(UStatus::fail_with_code(
                        UCode::NOT_FOUND,
                        format!("No listeners registered for topic: {:?}", &uuri),
                    ))
                }
                Entry::Occupied(mut e) => {
                    let occupied = e.get_mut();

                    if occupied.is_empty() {
                        return Err(UStatus::fail_with_code(
                            UCode::NOT_FOUND,
                            format!("No listeners registered for topic: {:?}", &uuri),
                        ));
                    }

                    for listener in occupied.iter() {
                        let task_listener = listener.clone();
                        let task_umessage = umessage.clone();
                        task::spawn(async move { task_listener.on_receive(task_umessage).await });
                    }
                }
            }

            Ok(())
        }
    }

    #[async_trait]
    impl UTransport for UPClientFoo {
        async fn send(&self, _message: UMessage) -> Result<(), UStatus> {
            todo!()
        }

        async fn receive(&self, _topic: UUri) -> Result<UMessage, UStatus> {
            todo!()
        }

        async fn register_listener(
            &self,
            topic: UUri,
            listener: Arc<dyn UListener>,
        ) -> Result<(), UStatus> {
            let mut topics_listeners = self.listeners.lock().unwrap();
            let listeners = topics_listeners.entry(topic).or_default();
            let identified_listener = ComparableListener::new(listener);
            let inserted = listeners.insert(identified_listener);

            return match inserted {
                true => Ok(()),
                false => Err(UStatus::fail_with_code(
                    UCode::ALREADY_EXISTS,
                    "UUri + UListener pair already exists!",
                )),
            };
        }

        async fn unregister_listener(
            &self,
            topic: UUri,
            listener: Arc<dyn UListener>,
        ) -> Result<(), UStatus> {
            let mut topics_listeners = self.listeners.lock().unwrap();
            let listeners = topics_listeners.entry(topic.clone());
            return match listeners {
                Entry::Vacant(_) => Err(UStatus::fail_with_code(
                    UCode::NOT_FOUND,
                    format!("No listeners registered for topic: {:?}", &topic),
                )),
                Entry::Occupied(mut e) => {
                    let occupied = e.get_mut();
                    let identified_listener = ComparableListener::new(listener);
                    let removed = occupied.remove(&identified_listener);

                    match removed {
                        true => Ok(()),
                        false => Err(UStatus::fail_with_code(
                            UCode::NOT_FOUND,
                            "UUri + UListener not found!",
                        )),
                    }
                }
            };
        }
    }

    #[derive(Clone, Debug)]
    struct ListenerBaz;
    #[async_trait]
    impl UListener for ListenerBaz {
        async fn on_receive(&self, msg: UMessage) {
            println!("Printing msg from ListenerBaz! received: {:?}", msg);
        }

        async fn on_error(&self, err: UStatus) {
            println!("Printing err from ListenerBaz! received {:?}", err)
        }
    }

    #[derive(Clone, Debug)]
    struct ListenerBar;
    #[async_trait]
    impl UListener for ListenerBar {
        async fn on_receive(&self, msg: UMessage) {
            println!("Printing msg from ListenerBar! received: {:?}", msg);
        }

        async fn on_error(&self, err: UStatus) {
            println!("Printing err from ListenerBar! received: {:?}", err);
        }
    }

    fn uuri_factory(uuri_index: u8) -> UUri {
        match uuri_index {
            1 => UUri {
                authority: Some(UAuthority {
                    name: Some("uuri_1".to_string()),
                    number: Some(Number::Ip(vec![192, 168, 1, 200])),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
            _ => UUri::default(),
        }
    }

    #[test]
    fn test_register_and_receive() {
        let up_client_foo = UPClientFoo::new();
        let uuri_1 = uuri_factory(1);
        let listener_baz: Arc<dyn UListener> = Arc::new(ListenerBaz);
        let register_res =
            task::block_on(up_client_foo.register_listener(uuri_1.clone(), listener_baz.clone()));
        assert!(register_res.is_ok());

        let umessage = UMessage::default();
        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert_eq!(check_on_receive_res, Ok(()));
    }

    #[test]
    fn test_register_and_unregister() {
        let up_client_foo = UPClientFoo::new();
        let uuri_1 = uuri_factory(1);
        let listener_baz: Arc<dyn UListener> = Arc::new(ListenerBaz);
        let register_res =
            task::block_on(up_client_foo.register_listener(uuri_1.clone(), listener_baz.clone()));
        assert!(register_res.is_ok());

        let umessage = UMessage::default();
        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert_eq!(check_on_receive_res, Ok(()));

        let unregister_res =
            task::block_on(up_client_foo.unregister_listener(uuri_1.clone(), listener_baz));
        assert!(unregister_res.is_ok());

        let umessage = UMessage::default();
        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert!(check_on_receive_res.is_err());
    }

    #[test]
    fn test_register_multiple_listeners_on_one_uuri() {
        let up_client_foo = UPClientFoo::new();
        let uuri_1 = uuri_factory(1);
        let listener_baz: Arc<dyn UListener> = Arc::new(ListenerBaz);
        let listener_bar: Arc<dyn UListener> = Arc::new(ListenerBar);

        let register_res =
            task::block_on(up_client_foo.register_listener(uuri_1.clone(), listener_baz.clone()));
        assert!(register_res.is_ok());

        let register_res =
            task::block_on(up_client_foo.register_listener(uuri_1.clone(), listener_bar.clone()));
        assert!(register_res.is_ok());

        let umessage = UMessage::default();
        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert_eq!(check_on_receive_res, Ok(()));

        let unregister_baz_res =
            task::block_on(up_client_foo.unregister_listener(uuri_1.clone(), listener_baz));
        assert!(unregister_baz_res.is_ok());
        let unregister_bar_res =
            task::block_on(up_client_foo.unregister_listener(uuri_1.clone(), listener_bar));
        assert!(unregister_bar_res.is_ok());

        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert!(check_on_receive_res.is_err());
    }

    #[test]
    fn test_if_no_listeners() {
        let up_client_foo = UPClientFoo::new();
        let uuri_1 = uuri_factory(1);

        let umessage = UMessage::default();
        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);

        assert!(check_on_receive_res.is_err());
    }

    #[test]
    fn test_register_multiple_same_listeners_on_one_uuri() {
        let up_client_foo = UPClientFoo::new();
        let uuri_1 = uuri_factory(1);

        let listener_baz: Arc<dyn UListener> = Arc::new(ListenerBaz);
        let register_res =
            task::block_on(up_client_foo.register_listener(uuri_1.clone(), listener_baz.clone()));
        assert!(register_res.is_ok());

        let register_res =
            task::block_on(up_client_foo.register_listener(uuri_1.clone(), listener_baz.clone()));
        assert!(register_res.is_err());

        let listener_baz_completely_different: Arc<dyn UListener> = Arc::new(ListenerBaz);
        let register_res = task::block_on(
            up_client_foo
                .register_listener(uuri_1.clone(), listener_baz_completely_different.clone()),
        );
        assert!(register_res.is_ok());

        let umessage = UMessage::default();
        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert_eq!(check_on_receive_res, Ok(()));

        let unregister_res = task::block_on(
            up_client_foo.unregister_listener(uuri_1.clone(), listener_baz_completely_different),
        );
        assert!(unregister_res.is_ok());

        let unregister_baz_res =
            task::block_on(up_client_foo.unregister_listener(uuri_1.clone(), listener_baz));
        assert!(unregister_baz_res.is_ok());

        let check_on_receive_res = up_client_foo.check_on_receive(&uuri_1, &umessage);
        assert!(check_on_receive_res.is_err());
    }
}
