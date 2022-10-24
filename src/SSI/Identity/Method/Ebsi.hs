{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TemplateHaskell    #-}

{-|

EBSI DID method implementation.

EBSI DID can be created for either Legal Persons and Natural Persons:
1. Legal Persons need to be registered with the EBSI ledger
2. Natural Persons are uniquely described by their public key material

EBSI DIDs for Natural Persons and their corresponding DID documents can derived from a JSON Web Key.

@
import SSI.Identity.Method.Ebsi

natural :: JWT -> Ebsi
natural = newDid

document :: JWT -> DidDocument
document = newDidDocument
@

-}
module SSI.Identity.Method.Ebsi
  (
    -- * EBSI DIDs
    Ebsi(..)
  , _Ebsi
  , _LegalPerson
  , _NaturalPerson

  -- * Creating EBSI DIDs
  , newDid
  , newDidDoc

  -- * Working with EBSI DIDs
  -- , resolver
  , validate
  ) where

import Control.Lens (Prism', makePrisms, preview, prism', re, review, view, (.~), (?~))
import Crypto.JOSE.JWK (JWK, Digest, SHA256, base64url, digest)
import Data.ByteString (ByteString)
import Data.Function ((&))
import Data.Text (Text)
import Data.Word (Word8)

import SSI.Identity.Did (Did(..), DidUrl(..), DidDocument(..), VerificationMethod(..), VerificationMethodKey(..), VerificationMethodReference(..), newDidUrl, didUrlFragment, newDidDocument, docController, docVerificationMethod, docAssertionMethod, docAuthentication)
import SSI.Types.Codec (base58btc, multibase, text, utf8, _Base58btc)

import qualified Control.Monad as Monad
import qualified Crypto.JOSE.JWK as Jwk
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Text.Encoding as TE

{-|

EBSI Decentralized Identifiers.

-}
data Ebsi
  = LegalPerson ByteString
  | NaturalPerson ByteString

makePrisms ''Ebsi

_Ebsi :: Prism' Did Ebsi
_Ebsi = prism' decoder encoder
  where
    encoder :: Did -> Maybe Ebsi
    encoder (Did method methodId) = Monad.guard (method == "ebsi") *> toIdentifier methodId

    decoder :: Ebsi -> Did
    decoder (LegalPerson bytes) = fromIdentifier 0x01 bytes
    decoder (NaturalPerson bytes) = fromIdentifier 0x02 bytes

    toIdentifier :: Text -> Maybe Ebsi
    toIdentifier t = case preview base58btc (TE.encodeUtf8 t) >>= BS.uncons of
      Just (0x01, i) | BS.length i == 16 -> Just $ LegalPerson i
      Just (0x02, i) | BS.length i == 32 -> Just $ NaturalPerson i
      _ -> Nothing

    fromIdentifier :: Word8 -> ByteString -> Did
    fromIdentifier version = Did "ebsi" . TE.decodeUtf8 . view (multibase . _Base58btc) . BS.cons version

-- | Derives a DID from a JSON Web Key.
newDid :: JWK -> Did
newDid jwk = did
  where
    thumbprint :: ByteString
    thumbprint = review digest (view Jwk.thumbprint jwk :: Digest SHA256)

    did :: Did
    did = Did "ebsi" $ TE.decodeUtf8 $ view (multibase . _Base58btc) $ BS.cons 0x01 thumbprint

-- | Derives a DID document from a JSON Web Key.
newDidDoc :: JWK -> DidDocument
newDidDoc jwk = newDidDocument did
  & docController .~ [did]
  & docVerificationMethod .~ Map.singleton url method
  & docAssertionMethod .~ [reference]
  & docAuthentication .~ [reference]
  where
    thumbprint :: ByteString
    thumbprint = view (re digest) (view Jwk.thumbprint jwk :: Digest SHA256)

    did :: Did
    did = Did "ebsi" $ TE.decodeUtf8 $ view base58btc $ BS.cons 0x01 thumbprint

    url :: DidUrl
    url = newDidUrl did & didUrlFragment ?~ view (base64url . utf8) thumbprint

    method :: VerificationMethod
    method = VerificationMethod url (review text did) did (PublicKeyJwk jwk)

    reference :: VerificationMethodReference
    reference = UrlReference url

-- | Validates an EBSI DID given a JSON Web Key.
validate :: JWK -> Did -> Bool
validate = (==) . newDid
