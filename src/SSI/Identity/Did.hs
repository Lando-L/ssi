{-# LANGUAGE DeriveGeneric          #-}
{-# LANGUAGE DerivingStrategies     #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE TemplateHaskell        #-}

{-|

Module      : SSI.Identity.Did
Description : Decentralized Identifiers (DIDs) v1.0 implementation
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Decentralized Identifiers (DIDs) v1.0 implementation.

A DID is a simple text string consisting of three parts:
1. the did URI scheme identifier
2. the identifier for the DID method
3. the DID method-specific identifier

-}
module SSI.Identity.Did
  (
  -- * Identifier creation
  -- $didCreation

  -- * Decentralized Identifiers
    Did(..)
  , HasDid(..)

  -- * Decentralized Identifier URLs
  , DidUrl(..)
  -- ** Smart constructor
  , newDidUrl
  -- ** Lenses
  , didUrlId
  , didUrlPath
  , didUrlQuery
  , didUrlFragment

  -- * Decentralized Identifier Documents
  , DidDocument(..)
  -- ** Smart constructor
  , newDidDocument
  -- ** Lenses
  , docId
  , docController
  , docVerificationMethod
  , docAuthentication
  , docAssertionMethod
  , docKeyAgreement
  , docCapabilityInvocation
  , docCapabilityDelegation
  , docService

  -- * Decentralized Identifier Document Metadata
  , DidDocumentMetadata(..)
  -- ** Smart constructor
  , emptyDidDocumentMetadata
  -- ** Lenses
  , docMetaCreated
  , docMetaUpdated
  , docMetaDeactivated
  , docMetaNextUpdate
  , docMetaNextVersionId
  , docMetaVersionId
  , docMetaEquivalentId
  , docMetaCanonicalId

  -- * Miscellaneous
  , VerificationMethod(..)
  , vmId
  , vmType
  , vmController
  , vmKey
  , VerificationMethodKey(..)
  , _PublicKeyJwk
  , _PublicKeyMultibase
  , VerificationMethodReference(..)
  , _UrlReference
  , _EmbeddedReference
  , Service(..)
  , serviceId
  , serviceType
  , serviceEndpoint
  ) where

import Control.Applicative (Alternative(..), optional)
import Control.Lens (makeClassy, makeLenses, makePrisms, (^.))
import Crypto.JWT (JWK)
import Data.Aeson (FromJSON(..), ToJSON(..), Value(..), (.:), (.:?), (.=), (.!=))
import Data.Aeson.Types (Pair)
import Data.Attoparsec.Text (Parser)
import Data.Bifunctor (Bifunctor(..))
import Data.Map.Strict (Map)
import Data.Text (Text)
import GHC.Generics (Generic)

import SSI.Types.Codec (FromText(..), ToText(..), Multibase(..))

import qualified Control.Monad as Monad
import qualified Data.Aeson as Json
import qualified Data.Aeson.Encoding as Json.Encoding
import qualified Data.Attoparsec.Text as Parser
import qualified Data.Char as C
import qualified Data.List as List
import qualified Data.Map.Strict as Map
import qualified Data.Maybe as Maybe
import qualified Data.Text as T

-- $didCreation
-- 
-- DIDs can be created manually using its constructor or parsed from a Text or JSON representation.
-- 
-- @
-- {-# LANGUAGE OverloadedStrings #-}
-- 
-- import Control.Lens
-- 
-- import SSI.Identity.Did
-- import SSI.Types.Codec
-- 
-- manual :: Did
-- manual = Did "example" "123456789abcdefghi"
-- 
-- parsed :: Maybe Did
-- parsed = preview text "did:example:123456789abcdefghi"
-- @
-- 
-- DID URLs are created in similar fashion, either using its smart constructor
-- or they are parsed from Text or JSON representations.
-- 
-- @
-- {-# LANGUAGE OverloadedStrings #-}
-- 
-- import Control.Lens
-- 
-- import SSI.Identity.Did
-- import SSI.Types.Codec
-- 
-- manual :: DidUrl
-- manual = newDidUrl (Did "example" "123456789abcdefghi")
--   & didUrlPath ?~ "path"
--   & didUrlFragment ?~ "keys-1"
-- 
-- parsed :: Maybe DidUrl
-- parsed = preview text "123456789abcdefghi/path#keys-1"
-- @
-- 
{-|

Decentralized Identifiers are uniquely described by a method-name and a method-specific-id.
This is a method agnostic representation of DIDs, each method may chose a more suitable representation
to describe its DIDs.

-}
data Did = Did
  { _didMethod :: !Text
  , _didMethodId :: !Text
  } deriving stock (Show, Eq, Generic, Ord)

makeClassy ''Did

instance FromText Did where
  parseText t = first (const t) $ Parser.parseOnly (didParser <* Parser.endOfInput) t

instance ToText Did where
  toText (Did method methodId) = T.intercalate ":" ["did", method, methodId]

instance FromJSON Did where
  parseJSON = Json.withText "Did" $ either (const empty) pure . parseText

instance ToJSON Did where
  toJSON = Json.String . toText
  toEncoding = Json.Encoding.text . toText

didParser :: Parser Did
didParser = Did <$> (Parser.string "did:" *> methodName) <*> (Parser.char ':' *> methodSpecificId)
  where
    methodName :: Parser Text
    methodName = T.pack <$> Parser.many1 methodChar

    methodSpecificId :: Parser Text
    methodSpecificId = T.pack . concat <$> (flip (:) <$> idMany <*> idSome)

    methodChar :: Parser Char
    methodChar = Parser.digit <|> Parser.satisfy (\c -> C.isLower c && C.isAlpha c)

    idMany :: Parser [String]
    idMany = many (flip (:) <$> (many idChar <|> pctEncoded) <*> Parser.char ':')

    idSome :: Parser String
    idSome = some idChar <|> pctEncoded

    idChar :: Parser Char
    idChar = Parser.letter <|> Parser.digit <|> Parser.satisfy (\c -> c == '.' || c == '-' || c == '_')

    pctEncoded :: Parser String
    pctEncoded = (:) <$> Parser.char '%' <*> Parser.count 2 (Parser.satisfy C.isHexDigit)

{-|

Decentralized Identifier URLs are network location identifiers for a specific resource.
It can be used to retrieve specific parts of a DID document, such as Verification Methods or Services.

-}
data DidUrl = DidUrl
  { _didUrlId :: !Did
  , _didUrlPath :: !(Maybe Text)
  , _didUrlQuery :: !(Maybe Text)
  , _didUrlFragment :: !(Maybe Text)
  } deriving stock (Show, Eq, Generic, Ord)

makeLenses ''DidUrl

instance HasDid DidUrl where
  did = didUrlId

instance FromText DidUrl where
  parseText t = first (const t) $ Parser.parseOnly (didUrlParser <* Parser.endOfInput) t

instance ToText DidUrl where
  toText (DidUrl _id path query fragment) = mconcat
    [ toText _id
    , Maybe.fromMaybe "" path
    , maybe "" ("?" <>) query
    , maybe "" ("#" <>) fragment
    ]

instance FromJSON DidUrl where
  parseJSON = Json.withText "DidUrl" $ either (const empty) pure . parseText

instance ToJSON DidUrl where
  toJSON = Json.String . toText
  toEncoding = Json.Encoding.text . toText

-- | Constructor for a minimal Decentralized Identifier Url
newDidUrl :: Did -> DidUrl
newDidUrl _id = DidUrl _id Nothing Nothing Nothing

didUrlParser :: Parser DidUrl
didUrlParser = DidUrl <$> didParser <*> pathParser <*> queryParser <*> fragmentParser
  where
    pathParser :: Parser (Maybe Text)
    pathParser = optional $ T.pack . concat <$> some ((:) <$> Parser.char '/' <*> segment)

    queryParser :: Parser (Maybe Text)
    queryParser = optional $ T.pack <$> (Parser.char '?' *> content)

    fragmentParser :: Parser (Maybe Text)
    fragmentParser = optional $ T.pack <$> (Parser.char '#' *> content)

    content :: Parser String
    content = many (pchar <|> Parser.char '/' <|> Parser.char '?')

    segment :: Parser String
    segment = concat <$> many (many pchar <|> pctEncoded)

    pchar :: Parser Char
    pchar = unreserved <|> subDelimiter <|> Parser.satisfy (\c -> c == ':' && c == '@')

    pctEncoded :: Parser String
    pctEncoded =  (:) <$> Parser.char '%' <*> Parser.count 2 (Parser.satisfy C.isHexDigit)

    unreserved :: Parser Char
    unreserved = Parser.letter <|> Parser.digit <|> Parser.satisfy (\c -> c == '.' || c == '-' || c == '_' || c == '~')

    subDelimiter :: Parser Char
    subDelimiter = Parser.satisfy $ flip elem ['!', '$', '&', '\'', '(', ')', '*', '+', ',', '='] -- Removed ';' char

{-|

Verification Method Keys describe the key material needed to apply a Verification Method.
Two supported Verification Method Keys are PublicKeyJwk and PublicKeyMultibase.

-}
data VerificationMethodKey
  = PublicKeyJwk JWK
  -- ^ A JSON Web Key that conforms to (RFC 7517).
  | PublicKeyMultibase Multibase
  -- ^ A string representation of a Multibase encoded public key.
  deriving stock (Show, Eq, Generic)

makePrisms ''VerificationMethodKey

{-|

Verification Methods declare cryptographic public keys used to authenticate or authorize interactions
with the DID subject or associated parties.

-}
data VerificationMethod = VerificationMethod
  { _vmId :: !DidUrl
  , _vmType :: !Text
  , _vmController :: !Did
  , _vmKey :: !VerificationMethodKey
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerificationMethod

instance FromJSON VerificationMethod where
  parseJSON = Json.withObject "VerificationMethod" $ \v -> VerificationMethod
    <$> v .: "id"
    <*> v .: "type"
    <*> v .: "controller"
    <*> ((PublicKeyJwk <$> v .: "publicKeyJwk") <|> (PublicKeyMultibase <$> v .: "publicKeyMultibase"))

instance ToJSON VerificationMethod where
  toJSON (VerificationMethod _id _type controller key) = Json.object
    [ "id" .= _id
    , "type" .= _type
    , "controller" .= controller
    , case key of
      PublicKeyJwk jwk -> "publicKeyJwk" .= jwk
      PublicKeyMultibase base -> "publicKeyMultibase" .= base
    ]

{-|

Verification Method References are references to Verification Methods and allow them to be
used by more than one Verification Relationship. References are either embedded or encoded as URLs.

-}
data VerificationMethodReference
  = UrlReference DidUrl
  -- ^ URL References reference Verification Methods that might be used by more than one verification relationship
  | EmbeddedReference VerificationMethod
  -- ^ Embedded References declare embedded Verification Methods that may *only* be used for one verification relationship.
  deriving stock (Show, Eq, Generic)

makePrisms ''VerificationMethodReference

instance FromJSON VerificationMethodReference where
  parseJSON v = (UrlReference <$> parseJSON v) <|> (EmbeddedReference <$> parseJSON v)

instance ToJSON VerificationMethodReference where
  toJSON (UrlReference url) = toJSON url
  toJSON (EmbeddedReference method) = toJSON method

  toEncoding (UrlReference url) = toEncoding url
  toEncoding (EmbeddedReference method) = toEncoding method

{-|

Services are used to express ways of communicating with the DID subject or associated parties.
A service can be any type of service the DID subject wants to advertise, including
decentralized identity management services for further discovery, authentication, authorization, or interaction.

-}
data Service = Service
  { _serviceId :: !DidUrl
  , _serviceType :: !Text
  , _serviceEndpoint :: !Text
  } deriving stock (Show, Eq, Generic)

makeLenses ''Service

instance FromJSON Service where
  parseJSON = Json.withObject "Service" $ \v -> Service
    <$> v .: "id"
    <*> v .: "type"
    <*> v .: "serviceEndpoint"

instance ToJSON Service where
  toJSON (Service _id _type endpoint) = Json.object
    [ "id" .= _id
    , "type" .= _type
    , "serviceEndpoint" .= endpoint
    ]

  toEncoding (Service _id _type endpoint) = Json.pairs $ mconcat
    [ "id" .= _id
    , "type" .= _type
    , "serviceEndpoint" .= endpoint
    ]

{-|

DID documents are uniquely associated with a DID and express how to interact and communicate
with the DID subject or associated parties. The resolution of a DID to its corresponding DID document
depends on the specific DID method.

-}
data DidDocument = DidDocument
  { _docId :: !Did
  , _docController :: ![Did]
  , _docVerificationMethod :: !(Map DidUrl VerificationMethod)
  , _docAuthentication :: ![VerificationMethodReference]
  , _docAssertionMethod :: ![VerificationMethodReference]
  , _docKeyAgreement :: ![VerificationMethodReference]
  , _docCapabilityInvocation :: ![VerificationMethodReference]
  , _docCapabilityDelegation :: ![VerificationMethodReference]
  , _docService :: !(Map DidUrl Service)
  } deriving stock (Show, Eq, Generic)

makeLenses ''DidDocument

docContext :: Text
docContext = "https://www.w3.org/ns/did/v1"

instance HasDid DidDocument where
  did = docId

instance FromJSON DidDocument where
  parseJSON = Json.withObject "DidDocument" $ \v -> do
    context <- v .: "@context"
    Monad.guard ([docContext] `List.isPrefixOf` context)
    DidDocument
      <$> v .: "id"
      <*> v .:? "controller" .!= []
      <*> fmap (Map.fromList . fmap (\method -> (method ^. vmId, method))) (v .:? "verificationMethod" .!= [])
      <*> v .:? "authentication" .!= []
      <*> v .:? "assertionMethod" .!= []
      <*> v .:? "keyAgreement" .!= []
      <*> v .:? "capabilityInvocation" .!= []
      <*> v .:? "capabilityDelegation" .!= []
      <*> fmap (Map.fromList . fmap (\service -> (service ^. serviceId, service))) (v .:? "service" .!= [])

instance ToJSON DidDocument where
  toJSON (DidDocument _id ctr mtd aut ass kag civ cde ser) = Json.object $ filter nonEmpty
    [ "@context" .= [docContext]
    , "id" .= _id
    , "controller" .= ctr
    , "verificationMethod" .= Map.elems mtd
    , "authentication" .= aut
    , "assertionMethod" .= ass
    , "keyAgreement" .= kag
    , "capabilityInvocation" .= civ
    , "capabilityDelegation" .= cde
    , "service" .= Map.elems ser
    ]
    where
      nonEmpty :: Pair -> Bool
      nonEmpty (_, Object v) = not (null v)
      nonEmpty (_, Array v) = not (null v)
      nonEmpty _ = True

-- | Constructor for a minimal Decentralized Identifier Document
newDidDocument :: Did -> DidDocument
newDidDocument _id = DidDocument _id [] Map.empty [] [] [] [] [] Map.empty

{-|

DID documents metadata extends DID document resolution with associated metadata.

-}
data DidDocumentMetadata = DidDocumentMetadata
  { _docMetaCreated :: !(Maybe Text)
  , _docMetaUpdated :: !(Maybe Text)
  , _docMetaDeactivated :: !(Maybe Bool)
  , _docMetaNextUpdate :: !(Maybe Text)
  , _docMetaVersionId :: !(Maybe Text)
  , _docMetaNextVersionId :: !(Maybe Text)
  , _docMetaEquivalentId :: !(Maybe Text)
  , _docMetaCanonicalId :: !(Maybe Text)
  } deriving stock (Show, Eq, Generic)

makeLenses ''DidDocumentMetadata

instance FromJSON DidDocumentMetadata where
  parseJSON = Json.withObject "DidDocumentMetadata" $ \v -> DidDocumentMetadata
    <$> v .: "created"
    <*> v .: "updated"
    <*> v .: "deactivated"
    <*> v .: "nextUpdate"
    <*> v .: "versionId"
    <*> v .: "nextVersionId"
    <*> v .: "equivalentId"
    <*> v .: "canonicalId"

instance ToJSON DidDocumentMetadata where
  toJSON (DidDocumentMetadata crt upd dea nup vid nvi eid cid) = Json.object
    [ "created" .= crt
    , "updated" .= upd
    , "deactivated" .= dea
    , "nextUpdate" .= nup
    , "versionId" .= vid
    , "nextVersionId" .= nvi
    , "equivalentId" .= eid
    , "canonicalId" .= cid
    ]

  toEncoding (DidDocumentMetadata crt upd dea nup vid nvi eid cid) = Json.pairs $ mconcat
    [ "created" .= crt
    , "updated" .= upd
    , "deactivated" .= dea
    , "nextUpdate" .= nup
    , "versionId" .= vid
    , "nextVersionId" .= nvi
    , "equivalentId" .= eid
    , "canonicalId" .= cid
    ]

-- | Constructor for a minimal Decentralized Identifier Document Metadata
emptyDidDocumentMetadata :: DidDocumentMetadata
emptyDidDocumentMetadata = DidDocumentMetadata Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing
