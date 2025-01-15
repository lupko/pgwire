use std::fmt::Debug;

use async_trait::async_trait;
use futures::sink::{Sink, SinkExt};

use super::{AuthSource, AuthenticationEventHandler, ClientInfo, LoginInfo, PgWireConnectionState, ServerParameterProvider, StartupHandler};
use crate::error::{ErrorInfo, PgWireError, PgWireResult};
use crate::messages::response::ErrorResponse;
use crate::messages::startup::Authentication;
use crate::messages::{PgWireBackendMessage, PgWireFrontendMessage};

#[derive(new)]
pub struct CleartextPasswordAuthStartupHandler<A, P, E> {
    auth_source: A,
    parameter_provider: P,
    event_handler: E
}

#[async_trait]
impl<V: AuthSource, P: ServerParameterProvider, E: AuthenticationEventHandler> StartupHandler
    for CleartextPasswordAuthStartupHandler<V, P, E>
{
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        match message {
            PgWireFrontendMessage::Startup(ref startup) => {
                super::save_startup_parameters_to_metadata(client, startup);
                client.set_state(PgWireConnectionState::AuthenticationInProgress);
                client
                    .send(PgWireBackendMessage::Authentication(
                        Authentication::CleartextPassword,
                    ))
                    .await?;
            }
            PgWireFrontendMessage::PasswordMessageFamily(pwd) => {
                let pwd = pwd.into_password()?;
                let login_info = LoginInfo::from_client_info(client);
                let pass = self.auth_source.get_password(&login_info).await?;
                if pass.password == pwd.password.as_bytes() {
                    self.event_handler.on_authentication_succeeded(&login_info).await;

                    super::finish_authentication(client, &self.parameter_provider).await?;
                } else {
                    self.event_handler.on_authentication_failed(&login_info).await;

                    let error_info = ErrorInfo::new(
                        "FATAL".to_owned(),
                        "28P01".to_owned(),
                        "Password authentication failed".to_owned(),
                    );
                    let error = ErrorResponse::from(error_info);

                    client
                        .feed(PgWireBackendMessage::ErrorResponse(error))
                        .await?;
                    client.close().await?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
