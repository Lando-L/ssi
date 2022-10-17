{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}

{-|

Module      : SSI.Credential.VerifiableCredential
Description : Verifiable Credentials (VCs) v1.1 implementation
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Verifiable Credentials (VCs) v1.1 implementation.

A verifiable credential can represent all of the same information that a physical credential represents.
The addition of technologies, such as digital signatures, makes verifiable credentials more tamper-evident
and more trustworthy than their physical counterparts.

At the current moment this library supports only the JSON Web Token (JWT) proof format.
Therefore, most of the Verifiable Credential API is based on the [jose](https://hackage.haskell.org/package/jose)
package for signing and verifiying JWTs.

-}

module SSI.Credential.VerifiableCredential
  (
  -- * Credential lifecycle
  -- $credential_lifecycle

  -- * Issuance and presentation
    issue
  , present

  -- * Verification
  , verifyCredential
  , verifyPresentation
  ) where

import Control.Lens (makeLenses, preview, re, review, view, _Just, (^.), (.~), (?~))
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except (MonadError(..))
import Control.Monad.Time (MonadTime)
import Crypto.JWT (AsJWTError(..), Audience(..), ClaimsSet, HasClaimsSet(..), HasJWSHeader, JWSHeader, JWTValidationSettings, MonadRandom, NumericDate(..), SignedJWT, VerificationKeyStore(..), stringOrUri)
import Crypto.JOSE.Error (AsError(..))
import Crypto.JOSE.Header (HasJwk(..), HasKid(..), HasTyp(..), HeaderParam(..), param)
import Crypto.JOSE.JWK (Digest, JWK, SHA256, digest, thumbprint)
import Data.Aeson (FromJSON(..), ToJSON(..), Value (..), (.:), (.=))
import Data.Aeson.KeyMap (KeyMap)
import Data.Function ((&))
import Data.Functor (($>))
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

import SSI.Identity.Did (Did, DidUrl, VerificationMethod, did, newDidUrl, didUrlFragment, vmKey, _PublicKeyJwk)
import SSI.Identity.Resolver (Resolver)
import SSI.Types.Codec (base64url, text, utf8)

import qualified Control.Monad as Monad
import qualified Crypto.JWT as Jwt
import qualified Data.Aeson as Json
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Maybe as Maybe
import qualified Data.List as List
import qualified Data.Text.Encoding as TE

-- $credential_lifecycle
-- 
-- An issuer can assert claims about one or more subjects, creating a verfiable credential from these claims,
-- and transmitting the verifiable credential to a holder. The holder then may choose to present one or more
-- verifiable credentials, issued by one or more issuers, to a verifier. Verifable presentations are tamper
-- evident presentations of credentials in such a way that authorship of the data can be trusted after a
-- process of cryptographic verification.
-- 
-- For example:
-- 
-- @
-- import Crypto.JWT
-- import Data.Aeson
-- import Data.Time.Clock
-- import SSI.Credential.VerifiableCredential
-- import SSI.Identity.Did
-- import SSI.Types.Error
-- 
-- issuer :: Did
-- issuer = Did "example" "issuer"
-- 
-- subject :: Did
-- subject = Did "example" "subject"
-- 
-- verifier :: Did
-- verifier = Did "example" "verifier"
-- 
-- doIssue :: JWK -> DidUrl -> Value -> UTCTime -> UTCTime -> Maybe UTCTime -> IO (Either SsiError Text)
-- doIssue issuerKey issuerRef crd iat nbf exn = runJOSE $ issue issuerKey issuerRef "1" subject crd iat nbf exn
-- 
-- doPresent :: JWK -> UTCTime -> UTCTime -> Maybe UTCTime -> Text -> [Text] -> IO (Either SsiError Text)
-- doPresent subjectKey iat nbf exn nonce = runJOSE . present subjectKey subject "1" verifier iat nbf exn nonce
-- 
-- doVerify :: Text -> Resolver IO DidUrl VerificationMethod -> Text -> IO (Either SsiError [Value])
-- doVerify nonce resolver = runJOSE . verifyCredentials nonce resolver verifier
-- @

data VerifiableCredential = VerifiableCredential
  { _vcClaims :: !ClaimsSet
  , _vcCredentials :: !Value
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerifiableCredential

vcContext :: Text
vcContext = "https://www.w3.org/2018/credentials/v1"

vcType :: Text
vcType = "VerifiableCredential"

instance HasClaimsSet VerifiableCredential where
  claimsSet = vcClaims

instance FromJSON VerifiableCredential where
  parseJSON = Json.withObject "VerifiableCredential" $ \v -> do
    context <- (v .: "vc") >>= (.: "@context")
    types <- (v .: "vc") >>= (.: "type")
    Monad.guard (List.isPrefixOf [vcContext] context && List.isPrefixOf [vcType] types)
    claims <- parseJSON (Object v)
    creds <- (v .: "vc") >>= (.: "credentialSubject")
    return $ VerifiableCredential claims creds

instance ToJSON VerifiableCredential where
  toJSON (VerifiableCredential claims creds) = case toJSON claims of
    Object v -> Object $ KeyMap.insert "vc" vc v
    v -> v
    where
      vc :: Value
      vc = Json.object ["@context" .= [vcContext], "type" .= [vcType], "credentialSubject" .= creds]

-- | Create a verifiable credential from a set of claims.
issue
  :: (MonadError e m, MonadRandom m, AsError e)
  => JWK
  -- ^ The issuer's JSON Web Key used for singing the credentials.
  -> DidUrl
  -- ^ The resolvable reference to the public parts of the issuer's signing key.
  -> Text
  -- ^ The id of the JSON Web Token.
  -> Did
  -- ^ The DID of the subject of the credentials.
  -> Value
  -- ^ The credentials encoded as a JSON value.
  -> UTCTime
  -- ^ The timestamp marking the time of issuance.
  -> UTCTime
  -- ^ The timestamp marking the beginning of validity.
  -> Maybe UTCTime
  -- ^ The timestamp marking the end of validity.
  -> m Text
  -- ^ The verifiable credential encoded as a JSON Web Token.
issue key ref _id sub crd iat nbf exn = fmap encode $ header >>= sign credential
  where
    sign :: (MonadError e m, MonadRandom m, AsError e) => VerifiableCredential -> JWSHeader () -> m SignedJWT
    sign c h = Jwt.signJWT key h c

    encode :: SignedJWT -> Text
    encode = TE.decodeUtf8 . BSL.toStrict . Jwt.encodeCompact

    header :: (MonadError e m, AsError e) => m (JWSHeader ())
    header = do
      alg <- Jwt.bestJWSAlg key
      Jwt.newJWSHeader ((), alg)
        & typ ?~ HeaderParam () "JWT"
        & kid ?~ HeaderParam () (review text ref)
        & return

    claims :: ClaimsSet
    claims = Jwt.emptyClaimsSet
      & claimJti ?~ _id
      & claimIss .~ preview stringOrUri (view (did . re text) ref)
      & claimSub .~ preview stringOrUri (review text sub)
      & claimAud .~ fmap (Audience . List.singleton) (preview stringOrUri (review text sub))
      & claimIat ?~ NumericDate iat
      & claimNbf ?~ NumericDate nbf
      & claimExp .~ fmap NumericDate exn

    credential :: VerifiableCredential
    credential = VerifiableCredential claims crd

data VerifiablePresentation = VerifiablePresentation
  { _vpClaims :: !ClaimsSet
  , _vpCredentials :: ![Text]
  , _vpNonce :: !Text
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerifiablePresentation

vpContext :: Text
vpContext = "https://www.w3.org/2018/credentials/v1"

vpType :: Text
vpType = "VerifiableCredential"

instance HasClaimsSet VerifiablePresentation where
  claimsSet f h@(VerifiablePresentation { _vpClaims = a }) = fmap (\a' -> h{ _vpClaims = a' }) (f a)

instance FromJSON VerifiablePresentation where
  parseJSON = Json.withObject "VerifiablePresentation" $ \v -> do
    context <- (v .: "vp") >>= (.: "@context")
    types <- (v .: "vp") >>= (.: "type")
    Monad.guard (List.isPrefixOf [vpContext] context && List.isPrefixOf [vpType] types)
    claims <- parseJSON (Object v)
    creds <- (v .: "vp") >>= (.: "verifiableCredentials")
    nonce <- v .: "nonce"
    return $ VerifiablePresentation claims creds nonce

instance ToJSON VerifiablePresentation where
  toJSON (VerifiablePresentation claims creds nonce) = case toJSON claims of
    Object v -> Object $ KeyMap.union v ext
    v -> v
    where
      ext :: KeyMap Value
      ext = KeyMap.fromList
        [ ("nonce", Json.String nonce)
        , ( "vp"
          , Json.object
            [ "@context" .= [vpContext]
            , "type" .= [vpType]
            , "verifiableCredentials" .= creds
            ]
          )
        ]

-- | Create a verifiable presentation from a set of JWT encoded verifiable credentials.
present
  :: (MonadError e m, MonadRandom m, AsError e)
  => JWK
  -- ^ The subject's JSON Web Key used for signing the presentation.
  -> Did
  -- ^ The subject's DID.
  -> Text
  -- ^ The id of the JSON Web Token.
  -> Did
  -- ^ The DID of the verifier.
  -> UTCTime
  -- ^ The timestamp marking the time of issuance.
  -> UTCTime
  -- ^ The timestamp marking the beginning of validity.
  -> Maybe UTCTime
  -- ^ The timestamp marking the end of validity.
  -> Text
  -- ^ The unique nonce used for the presentation.
  -> [Text]
  -- ^ The presented verfiable credentials encoded as JSON Web Tokens.
  -> m Text
  -- ^ The verifiable presentation encoded as a JSON Web Token.
present key sub _id aud iat nbf exn non crd = fmap encode $ header >>= sign presentation
  where
    sign :: (MonadError e m, MonadRandom m, AsError e) => VerifiablePresentation -> JWSHeader () -> m SignedJWT
    sign c h = Jwt.signJWT key h c

    encode :: SignedJWT -> Text
    encode = TE.decodeUtf8 . BSL.toStrict . Jwt.encodeCompact

    header :: (MonadError e m, AsError e) => m (JWSHeader ())
    header = do
      alg <- Jwt.bestJWSAlg key
      Jwt.newJWSHeader ((), alg)
        & typ ?~ HeaderParam () "JWT"
        & kid ?~ HeaderParam () (review text ref)
        & jwk ?~ HeaderParam () key
        & return

    presentation :: VerifiablePresentation
    presentation = VerifiablePresentation claims crd non

    claims :: ClaimsSet
    claims = Jwt.emptyClaimsSet
      & claimJti ?~ _id
      & claimIss .~ preview stringOrUri (review text sub)
      & claimSub .~ preview stringOrUri (review text sub)
      & claimAud .~ fmap (Audience . List.singleton) (preview stringOrUri (review text aud))
      & claimIat ?~ NumericDate iat
      & claimNbf ?~ NumericDate nbf
      & claimExp .~ fmap NumericDate exn

    ref :: DidUrl
    ref = newDidUrl sub & didUrlFragment ?~ fragment

    fragment :: Text
    fragment = view (re (base64url . digest) . utf8) (view thumbprint key :: Digest SHA256)

newtype Validator a = Validator a

instance (Applicative m, HasJWSHeader h) => VerificationKeyStore m (h p) VerifiableCredential (Validator (Resolver m DidUrl VerificationMethod)) where
  getVerificationKeys h _ (Validator resolve) = Maybe.maybeToList . (=<<) key <$> traverse resolve ref
    where
      ref :: Maybe DidUrl
      ref = preview (kid . _Just . param . text) h

      key :: VerificationMethod -> Maybe JWK
      key = preview (vmKey . _PublicKeyJwk)

instance (Applicative m, HasJWSHeader h) => VerificationKeyStore m (h p) VerifiablePresentation (Validator Text) where
  getVerificationKeys h s (Validator nonce) = pure $ Maybe.maybeToList $ Monad.join $ verify <$> ref <*> key
    where
      verify :: Text -> JWK -> Maybe JWK
      verify r k = Monad.guard (r == fragment k && nonce == s ^. vpNonce) $> k

      ref :: Maybe Text
      ref = preview (kid . _Just . param . text . didUrlFragment . _Just) h

      key :: Maybe JWK
      key = preview (jwk . _Just . param) h

      fragment :: JWK -> Text
      fragment key' = view (re (base64url . digest) . utf8) (view thumbprint key' :: Digest SHA256)

-- | Verify a credential based on the given DID resolver.
verifyCredential
  :: (MonadError e m, MonadTime m, AsError e, AsJWTError e)
  => Resolver m DidUrl VerificationMethod
  -- ^ The dereferencer resolving DID-URLs into verification methods.
  -> Did
  -- ^ The audience of the verfiable credential.
  -> Text
  -- ^ The verfiable credential encoded as a JSON Web Token.
  -> m Value
  -- ^ The verified credentials encoded as a JSON value.
verifyCredential resolver aud jwt = fmap (view vcCredentials) (decode jwt >>= verify resolver)
  where
    decode :: (MonadError e m, AsError e) => Text -> m SignedJWT
    decode = Jwt.decodeCompact . BSL.fromStrict . TE.encodeUtf8

    verify
      :: (MonadError e m, MonadTime m, AsError e, AsJWTError e)
      => Resolver m DidUrl VerificationMethod
      -> SignedJWT
      -> m VerifiableCredential
    verify resolver' = Jwt.verifyJWT settings (Validator resolver')

    settings :: JWTValidationSettings
    settings = Jwt.defaultJWTValidationSettings ((==) (preview stringOrUri (review text aud)) . Just)

-- | Verify a presentation based on the given nonce and DID resolver.
verifyPresentation
  :: (MonadError e m, MonadTime m, AsError e, AsJWTError e)
  => Text
  -- ^ The unique nonce used for the presentation.
  -> Resolver m DidUrl VerificationMethod
  -- ^ The dereferencer resolving DID-URLs into verification methods.
  -> Did
  -- ^ The audience of the verfiable credential.
  -> Text
  -- ^ The verfiable presentation encoded as a JSON Web Token.
  -> m [Value]
  -- ^ The verified credentials presented in the verifiable presentation encoded as JSON values.
verifyPresentation nonce resolver aud jwt = decode jwt >>= verify nonce >>= validate resolver
  where
    decode :: (MonadError e m, AsError e) => Text -> m SignedJWT
    decode = Jwt.decodeCompact . BSL.fromStrict . TE.encodeUtf8

    verify :: (MonadError e m, MonadTime m, AsError e, AsJWTError e) => Text -> SignedJWT -> m VerifiablePresentation
    verify nonce' = Jwt.verifyJWT settings (Validator nonce')

    validate
      :: (MonadError e m, MonadTime m, AsError e, AsJWTError e)
      => Resolver m DidUrl VerificationMethod
      -> VerifiablePresentation
      -> m [Value]
    validate resolver' presentation = case preview (vpClaims . claimSub . _Just . re stringOrUri . text) presentation of
      Nothing -> throwing _JWTClaimsSetDecodeError "ClaimsSet subject is not a valid DID"
      Just sub -> traverse (verifyCredential resolver' sub) (presentation ^. vpCredentials)

    settings :: JWTValidationSettings
    settings = Jwt.defaultJWTValidationSettings ((==) (preview stringOrUri (review text aud)). Just)
