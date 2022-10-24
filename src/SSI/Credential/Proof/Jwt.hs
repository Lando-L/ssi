{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE UndecidableInstances       #-}

{-|

Module      : SSI.Credential.Proof.Jwt
Description : JSON Web Token proof format for Verifiable Credentials
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

JSON Web Token proof format for Verifiable Credentials.

-}
module SSI.Credential.Proof.Jwt
  (
  -- * Credential lifecycle
  -- $credentialLifecycle

  -- * Proof for verifiable credentials
    signCredential
  , verifyCredential

  -- * Proof for verifiable presentations
  , signPresentation
  , verifyPresentation
  ) where

import Control.Lens (makeLenses, preview, re, review, view, _Just, (.~), (?~), (^.))
import Control.Monad.Error.Lens (throwing, throwing_)
import Control.Monad.Except (MonadError(..))
import Control.Monad.Time (MonadTime)
import Crypto.JOSE (MonadRandom)
import Crypto.JOSE.Error (AsError(..))
import Crypto.JOSE.Header (HeaderParam(..), HasTyp(..), HasKid(..), HasJwk(..), param)
import Crypto.JOSE.JWK (JWK, Digest, SHA256, digest, thumbprint)
import Crypto.JOSE.JWS (Alg, HasJWSHeader, JWSHeader)
import Crypto.JWT (AsJWTError(..), Audience(..), ClaimsSet, HasClaimsSet(..), JWTValidationSettings, NumericDate(..), SignedJWT, _JWTClaimsSetDecodeError, stringOrUri)
import Data.Aeson (FromJSON(..), ToJSON(..), (.:), (.=))
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.Types (Value(..))
import Data.Function ((&))
import Data.Functor (($>))
import Data.Text (Text)
import GHC.Generics (Generic)

import SSI.Credential.VerifiableCredential (VerifiableCredential, VerifiablePresentation, vcCredentials, vcSubject, vcIssued, vcValidFrom, vcValidUntil, vpIssued, vpValidFrom, vpValidUntil, vpCredentials, vcId, vpId)
import SSI.Credential.Proof.SigningKeyStore (SigningKeyStore(..))
import SSI.Credential.Proof.VerificationKeyStore (VerificationKeyStore(..), AsVerificationError(..))
import SSI.Identity.Did (Did, HasDid(..), DidUrl, VerificationMethod, vmKey, _PublicKeyJwk, didUrlFragment, newDidUrl)
import SSI.Identity.Resolver (Resolver)
import SSI.Types.Codec (base64url, text, utf8)

import qualified Control.Monad as Monad
import qualified Crypto.JWT as Jwt
import qualified Data.Aeson as Json
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import qualified Data.List as List
import qualified Data.Text.Encoding as TE

-- $credentialLifecycle
-- 
-- An issuer can assert claims about one or more subjects, creating a verfiable credential from these claims,
-- and transmitting the verifiable credential to a holder. The holder then may choose to present one or more
-- verifiable credentials, issued by one or more issuers, to a verifier. Verifable presentations are tamper
-- evident presentations of credentials in such a way that authorship of the data can be trusted after a
-- process of cryptographic verification.
-- 
-- Verifiable credentials may be issued and verified like this:
-- 
-- @
-- {-# LANGUAGE FlexibleContexts   #-}
-- {-# LANGUAGE OverloadedStrings  #-}
-- 
-- import Control.Lens
-- import Crypto.JOSE.JWK
-- import Data.Aeson
-- import Data.Text
-- 
-- import SSI.Credential.Proof.Jwt
-- import SSI.Credential.VerifiableCredential
-- import SSI.Error
-- import SSI.Identity.Did
-- import SSI.Identity.Resolver
-- 
-- issuer :: Did
-- issuer = Did "example" "issuer"
-- 
-- subject :: Did
-- subject = Did "example" "subject"
-- 
-- ref :: Did -> DidUrl
-- ref did = newDidUrl did & didUrlFragment ?~ "keys-1"
-- 
-- doIssue :: JWK -> VerifiableCredential -> IO (Either SsiError Text)
-- doIssue jwk = runSsi . signCredential jwk (ref issuer)
-- 
-- doVerify :: Resolver DidUrl (Ssi SsiError IO) VerificationMethod -> Text -> IO (Either SsiError Value)
-- doVerify resolver = runSsi . verifyCredential resolver subject
-- @
-- 
-- Verifiable presentations may be presented and verified like this:
-- 
-- @
-- {-# LANGUAGE FlexibleContexts   #-}
-- {-# LANGUAGE OverloadedStrings  #-}
-- 
-- import Crypto.JOSE.JWK
-- import Data.Aeson
-- import Data.Text
-- 
-- import SSI.Credential.Proof.Jwt
-- import SSI.Credential.VerifiableCredential
-- import SSI.Error
-- import SSI.Identity.Did
-- import SSI.Identity.Resolver
-- 
-- subject :: Did
-- subject = Did "example" "subject"
-- 
-- verifier :: Did
-- verifier = Did "example" "verifier"
-- 
-- doPresent :: JWK -> VerifiablePresentation -> IO (Either SsiError Text)
-- doPresent jwk = runSsi . signPresentation jwk subject verifier "nonce"
-- 
-- doVerify :: Resolver DidUrl (Ssi SsiError IO) VerificationMethod -> Text -> IO (Either SsiError [Value])
-- doVerify resolver = runSsi . verifyPresentation "nonce" resolver verifier
-- @

data VerifiableCredentialClaims = VerifiableCredentialClaims
  { _vccClaims :: !ClaimsSet
  , _vccCredentials :: !Value
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerifiableCredentialClaims

instance HasClaimsSet VerifiableCredentialClaims where
  claimsSet = vccClaims

instance FromJSON VerifiableCredentialClaims where
  parseJSON = Json.withObject "VerifiableCredentialClaims" $ \v -> do
    context <- (v .: "vc") >>= (.: "@context")
    types <- (v .: "vc") >>= (.: "type")
    Monad.guard (List.isPrefixOf [vcContext] context && List.isPrefixOf [vcType] types)
    claims <- parseJSON (Object v)
    creds <- (v .: "vc") >>= (.: "credentialSubject")
    return $ VerifiableCredentialClaims claims creds

instance ToJSON VerifiableCredentialClaims where
  toJSON (VerifiableCredentialClaims claims creds) = case toJSON claims of
    Object v -> Object $ KeyMap.insert "vc" vc v
    v -> v
    where
      vc :: Value
      vc = Json.object ["@context" .= [vcContext], "type" .= [vcType], "credentialSubject" .= creds]

instance (MonadError e m, AsVerificationError e, HasJWSHeader h) => VerificationKeyStore m (h p) VerifiableCredentialClaims (Resolver DidUrl m VerificationMethod) where
  getVerificationKeys h _ resolve = do
    method <- traverse resolve ref
    case method >>= key of
      Nothing -> throwing_ _VerificationJWKNotFound
      Just k -> pure [k]
    where
      ref :: Maybe DidUrl
      ref = preview (kid . _Just . param . text) h

      key :: VerificationMethod -> Maybe JWK
      key = preview (vmKey . _PublicKeyJwk)

vcContext :: Text
vcContext = "https://www.w3.org/2018/credentials/v1"

vcType :: Text
vcType = "VerifiableCredential"

vcToClaims :: Did -> VerifiableCredential -> VerifiableCredentialClaims
vcToClaims issuer vc = VerifiableCredentialClaims claims credentials
  where
    claims :: ClaimsSet
    claims = Jwt.emptyClaimsSet
      & claimJti ?~ view vcId vc
      & claimIss .~ preview stringOrUri (review text issuer)
      & claimSub .~ preview stringOrUri (view (vcSubject . re text) vc)
      & claimAud .~ fmap (Audience . List.singleton) (preview stringOrUri (view (vcSubject . re text) vc))
      & claimIat ?~ NumericDate (view vcIssued vc)
      & claimNbf ?~ NumericDate (view vcValidFrom vc)
      & claimExp .~ fmap NumericDate (view vcValidUntil vc)

    credentials :: Value
    credentials = vc ^. vcCredentials

-- | Sign a verifiable credential.
signCredential
  :: (MonadError e m, SigningKeyStore a m, MonadRandom m, AsError e)
  => a
  -- ^ The signature key.
  -> DidUrl
  -- ^ The resolvable DID URL referencing the public part of the signature key.
  -> VerifiableCredential
  -- ^ The verifiable credential.
  -> m Text
  -- ^ The verifiable credential encoded as a JSON Web Token.
signCredential a ref vc = do
  key <- getSigningKey a
  alg <- Jwt.bestJWSAlg key
  jwt <- sign credential key $ header alg
  return $ encode jwt
  where
    header :: Alg -> JWSHeader ()
    header alg = Jwt.newJWSHeader ((), alg)
      & typ ?~ HeaderParam () "JWT"
      & kid ?~ HeaderParam () (review text ref)

    sign :: (MonadError e m, MonadRandom m, AsError e) => VerifiableCredentialClaims -> JWK -> JWSHeader () -> m SignedJWT
    sign c key h = Jwt.signJWT key h c

    encode :: SignedJWT -> Text
    encode = TE.decodeUtf8 . BSL.toStrict . Jwt.encodeCompact

    credential :: VerifiableCredentialClaims
    credential = vcToClaims (view did ref) vc

-- | Verify a verifiable credential.
verifyCredential
  :: (MonadError e m, MonadTime m, AsError e, AsJWTError e, AsVerificationError e)
  => Resolver DidUrl m VerificationMethod
  -- ^ The dereferencer resolving DID urls into verification methods.
  -> Did
  -- ^ The token's audience.
  -> Text
  -- ^ The verfiable credential encoded as a JSON Web Token.
  -> m Value
  -- ^ The verified credentials encoded as a JSON value.
verifyCredential resolver aud jwt = fmap (view vccCredentials) (decode jwt >>= verify resolver)
  where
    decode :: (MonadError e m, AsError e) => Text -> m SignedJWT
    decode = Jwt.decodeCompact . BSL.fromStrict . TE.encodeUtf8

    verify
      :: (MonadError e m, MonadTime m, AsError e, AsJWTError e, AsVerificationError e)
      => Resolver DidUrl m VerificationMethod
      -> SignedJWT
      -> m VerifiableCredentialClaims
    verify = Jwt.verifyJWT settings

    settings :: JWTValidationSettings
    settings = Jwt.defaultJWTValidationSettings ((==) (preview stringOrUri (review text aud)) . Just)

data VerifiablePresentationClaims = VerifiablePresentationClaims
  { _vpcClaims :: !ClaimsSet
  , _vpcCredentials :: ![Text]
  , _vpcNonce :: !Text
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerifiablePresentationClaims

instance HasClaimsSet VerifiablePresentationClaims where
  claimsSet = vpcClaims

instance FromJSON VerifiablePresentationClaims where
  parseJSON = Json.withObject "VerifiablePresentationClaims" $ \v -> do
    context <- (v .: "vp") >>= (.: "@context")
    types <- (v .: "vp") >>= (.: "type")
    Monad.guard (List.isPrefixOf [vpContext] context && List.isPrefixOf [vpType] types)
    claims <- parseJSON (Object v)
    creds <- (v .: "vp") >>= (.: "verifiableCredentials")
    nonce <- v .: "nonce"
    return $ VerifiablePresentationClaims claims creds nonce

instance ToJSON VerifiablePresentationClaims where
  toJSON (VerifiablePresentationClaims claims creds nonce) = case toJSON claims of
    Object v -> Object $ KeyMap.union v ext
    v -> v
    where
      ext :: KeyMap Value
      ext = KeyMap.fromList
        [ ("nonce", String nonce)
        , ( "vp"
          , Json.object
            [ "@context" .= [vpContext]
            , "type" .= [vpType]
            , "verifiableCredentials" .= creds
            ]
          )
        ]

instance (MonadError e m, AsVerificationError e, HasJWSHeader h) => VerificationKeyStore m (h p) VerifiablePresentationClaims Text where
  getVerificationKeys h s nonce = case Monad.join (verify <$> ref <*> key) of
    Nothing -> throwing_ _VerificationJWKNotFound
    Just k -> pure [k]
    where
      verify :: Text -> JWK -> Maybe JWK
      verify r k = Monad.guard (r == fragment k && nonce == s ^. vpcNonce) $> k

      ref :: Maybe Text
      ref = preview (kid . _Just . param . text . didUrlFragment . _Just) h

      key :: Maybe JWK
      key = preview (jwk . _Just . param) h

      fragment :: JWK -> Text
      fragment key' = view (re (base64url . digest) . utf8) (view thumbprint key' :: Digest SHA256)

vpContext :: Text
vpContext = "https://www.w3.org/2018/credentials/v1"

vpType :: Text
vpType = "VerifiableCredential"

vpToClaims :: Did -> Did -> Text -> VerifiablePresentation -> VerifiablePresentationClaims
vpToClaims iss aud nonce vp = VerifiablePresentationClaims claims credentials nonce
  where
    claims :: ClaimsSet
    claims = Jwt.emptyClaimsSet
      & claimJti ?~ view vpId vp
      & claimIss .~ preview stringOrUri (review text iss)
      & claimSub .~ preview stringOrUri (review text iss)
      & claimAud .~ fmap (Audience . List.singleton) (preview stringOrUri (review text aud))
      & claimIat ?~ NumericDate (view vpIssued vp)
      & claimNbf ?~ NumericDate (view vpValidFrom vp)
      & claimExp .~ fmap NumericDate (view vpValidUntil vp)

    credentials :: [Text]
    credentials = vp ^. vpCredentials

-- | Sign a verifiable presentation.
signPresentation
  :: (MonadError e m, SigningKeyStore a m, MonadRandom m, AsError e)
  => a
  -- ^ The signature key.
  -> Did
  -- ^ The token's issuer.
  -> Did
  -- ^ The token's audience.
  -> Text
  -- ^ The token's nonce.
  -> VerifiablePresentation
  -- ^ The verifiable presentation.
  -> m Text
  -- ^ The verifiable presentation encoded as a JSON Web Token.
signPresentation a iss aud nonce vp = do
  key <- getSigningKey a
  alg <- Jwt.bestJWSAlg key
  jwt <- sign key presentation $ header key alg
  return $ encode jwt
  where
    sign :: (MonadError e m, MonadRandom m, AsError e) => JWK -> VerifiablePresentationClaims -> JWSHeader () -> m SignedJWT
    sign key c h = Jwt.signJWT key h c

    encode :: SignedJWT -> Text
    encode = TE.decodeUtf8 . BSL.toStrict . Jwt.encodeCompact

    header :: JWK -> Alg -> JWSHeader ()
    header key alg = Jwt.newJWSHeader ((), alg)
      & typ ?~ HeaderParam () "JWT"
      & kid ?~ HeaderParam () (review text (ref key))
      & jwk ?~ HeaderParam () key

    ref :: JWK -> DidUrl
    ref key = newDidUrl iss & didUrlFragment ?~ fragment key

    fragment :: JWK -> Text
    fragment key = view (re (base64url . digest) . utf8) (view thumbprint key :: Digest SHA256)

    presentation :: VerifiablePresentationClaims
    presentation = vpToClaims (view did iss) aud nonce vp

-- | Verify a verifiable presentation.
verifyPresentation
  :: (MonadError e m, MonadTime m, AsError e, AsJWTError e, AsVerificationError e)
  => Text
  -- ^ The unique nonce used for the presentation.
  -> Resolver DidUrl m VerificationMethod
  -- ^ The dereferencer resolving DID-URLs into verification methods.
  -> Did
  -- ^ The audience of the verfiable credential.
  -> Text
  -- ^ The verfiable presentation encoded as a JSON Web Token.
  -> m [Value]
  -- ^ The verified credentials presented in the verifiable presentation encoded as JSON values.
verifyPresentation nonce resolver aud jwt = decode jwt >>= verify >>= validate resolver
  where
    decode :: (MonadError e m, AsError e) => Text -> m SignedJWT
    decode = Jwt.decodeCompact . BSL.fromStrict . TE.encodeUtf8

    verify
      :: (MonadError e m, MonadTime m, AsError e, AsJWTError e, AsVerificationError e)
      => SignedJWT
      -> m VerifiablePresentationClaims
    verify = Jwt.verifyJWT settings nonce

    validate
      :: (MonadError e m, MonadTime m, AsError e, AsJWTError e, AsVerificationError e)
      => Resolver DidUrl m VerificationMethod
      -> VerifiablePresentationClaims
      -> m [Value]
    validate resolver' presentation = case preview (vpcClaims . claimSub . _Just . re stringOrUri . text) presentation of
      Nothing -> throwing _JWTClaimsSetDecodeError "ClaimsSet subject is not a valid DID"
      Just sub -> traverse (verifyCredential resolver' sub) (presentation ^. vpcCredentials)

    settings :: JWTValidationSettings
    settings = Jwt.defaultJWTValidationSettings ((==) (preview stringOrUri (review text aud)). Just)
