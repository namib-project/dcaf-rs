use super::*;

impl AuthServerRequestCreationHint {
    /// Returns a new builder for this struct.
    pub fn builder() -> AuthServerRequestCreationHintBuilder {
        AuthServerRequestCreationHintBuilder::default()
    }
}

impl AuthServerRequestCreationHintBuilder {
    /// Validates this builder's fields for correctness.
    pub(crate) fn validate(&self) -> Result<(), AuthServerRequestCreationHintBuilderError> {
        // TODO: Check whether there are invariants to validate
        Ok(())
    }
}

impl AccessTokenRequest {
    /// Returns a new builder for this struct.
    pub fn builder() -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder::default()
    }
}

impl AccessTokenRequestBuilder {
    pub(crate) fn validate(&self) -> Result<(), AccessTokenRequestBuilderError> {
        // TODO: Check whether there are invariants to validate
        Ok(())
    }

    /// Sets the [ace_profile] field to an empty value, which indicates a request for the
    /// Authorization Server to respond with the ace_profile field in the response.
    pub fn ace_profile(&mut self) -> &mut Self {
        self.ace_profile = Some(Some(()));
        self
    }
}

impl AccessTokenResponse {
    pub fn builder() -> AccessTokenResponseBuilder {
        AccessTokenResponseBuilder::default()
    }
}

impl AccessTokenResponseBuilder {
    pub(crate) fn validate(&self) -> Result<(), AccessTokenResponseBuilderError> {
        // TODO: Check whether there are invariants to validate
        Ok(())
    }
}

impl ErrorResponse {
    pub fn builder() -> ErrorResponseBuilder {
        ErrorResponseBuilder::default()
    }
}

impl ErrorResponseBuilder {
    pub(crate) fn validate(&self) -> Result<(), ErrorResponseBuilderError> {
        // TODO: Check whether there are invariants to validate
        Ok(())
    }
}
