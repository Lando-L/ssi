{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE QuasiQuotes        #-}

module SSI.Identity.DidSpec
  ( spec
  ) where

import Control.Lens (preview, review, (.~), (?~))
import Crypto.JOSE.JWK (JWK)
import Data.Aeson (Result(..), Value)
import Data.Aeson.QQ.Simple (aesonQQ)
import Data.ByteString (ByteString)
import Data.Function ((&))
import Data.Text (Text)
import Test.Hspec (Spec, context, describe, it, shouldBe)

import SSI.Identity.Did (Did(..), DidUrl(..), DidDocument, VerificationMethod(..), VerificationMethodKey(..), VerificationMethodReference(..), newDidUrl, didUrlFragment, newDidDocument, docController, docVerificationMethod, docAuthentication, docService, newDidUrl, Service (Service))
import SSI.Types.Codec (Multibase(..), multibase, text)

import qualified Data.Aeson as Json
import qualified Data.Map.Strict as Map
import qualified Data.Text.Encoding as TE

spec :: Spec
spec = do
  didSpec
  didUrlSpec
  didDocSpec

didSpec :: Spec
didSpec = describe "Did" $ do
  describe "parser" $ do
    context "when give an invalid DID" $
      it "fails to parse the DID" $
        preview text invalid `shouldBe` (Nothing :: Maybe Did)

    context "when give a valid DID" $
      it "returns the parsed DID" $
        preview text valid `shouldBe` Just did
  
  describe "writer" $
    it "returns the written DID" $
      review text did `shouldBe` valid
  where
    invalid :: Text
    invalid = "did:example:12345789*abcdefghi"
    
    valid :: Text
    valid = "did:example:123456789abcdefghi"

    did :: Did
    did = Did "example" "123456789abcdefghi"

didUrlSpec :: Spec
didUrlSpec = describe "DidUrl" $ do
  describe "parser" $ do
    context "when given an invalid DID-URL" $
      it "returns the parsed DID-URL" $
        preview text invalid `shouldBe` (Nothing :: Maybe DidUrl)
    
    context "when given a valid DID-URL" $
      it "returns the parsed DID-URL" $
        preview text valid `shouldBe` Just url
  
  describe "writer" $
    it "returns the written DID-URL" $
      review text url `shouldBe` valid
  where
    invalid :: Text
    invalid = "did:example:1*2*3?service=agent&relativeRef=/credentials#keys-1"
    
    valid :: Text
    valid = "did:example:123?service=agent&relativeRef=/credentials#keys-1"

    url :: DidUrl
    url = DidUrl (Did "example" "123") Nothing (Just "service=agent&relativeRef=/credentials") (Just "keys-1")

didDocSpec :: Spec
didDocSpec = describe "DidDocument" $ do
  describe "parser" $
    it "returns the parsed DID document" $ do
      jwk <- decodedJwk
      mlt <- decodedMulitbaseKey
      Json.fromJSON encodedDidDocument `shouldBe` Success (decodedDidDocument docId jwk mlt)
  
  describe "writer" $
    it "returns the written DID document" $ do
      jwk <- decodedJwk
      mlt <- decodedMulitbaseKey
      Json.toJSON (decodedDidDocument docId jwk mlt) `shouldBe` encodedDidDocument
  where
    encodedDidDocument :: Value
    encodedDidDocument = [aesonQQ|{
      "@context":["https://www.w3.org/ns/did/v1"],
      "id":"did:example:123456789abcdefghi",
      "controller": ["did:example:123456789abcdefghi"],
      "verificationMethod": [
        {
          "id": "did:example:123456789abcdefghi#keys-1",
          "type": "JsonWebKey2020",
          "controller": "did:example:123456789abcdefghi",
          "publicKeyJwk": {
            "crv": "Ed25519",
            "kty": "OKP",
            "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
          }
        }
      ],
      "authentication": [
        "did:example:123456789abcdefghi#keys-1",
        {
          "id": "did:example:123456789abcdefghi#keys-2",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:example:123456789abcdefghi",
          "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
        }
      ],
      "service": [
        {
          "id": "did:example:123456789abcdefghi#linked-domain",
          "type": "LinkedDomains",
          "serviceEndpoint": "https://bar.example.com"
        }
      ]
    }|]

    decodedDidDocument :: Did -> JWK -> Multibase -> DidDocument
    decodedDidDocument did jwk mlt = newDidDocument did
      & docController .~ [did]
      & docVerificationMethod .~ Map.singleton (jwkId did) (jwkMethod did jwk)
      & docAuthentication .~ [UrlReference (jwkId did), EmbeddedReference (multibaseMethod did mlt)]
      & docService .~ Map.singleton (serviceId did) (service did)
    
    encodedJWK :: Value
    encodedJWK = [aesonQQ|{
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
    }|]

    decodedJwk :: MonadFail m => m JWK
    decodedJwk = case Json.fromJSON encodedJWK of
      Error str -> fail str
      Success jwk -> pure jwk

    encodedMultibaseKey :: ByteString
    encodedMultibaseKey = TE.encodeUtf8 "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"

    decodedMulitbaseKey :: MonadFail m => m Multibase
    decodedMulitbaseKey = case preview multibase encodedMultibaseKey of
      Nothing -> fail "Could not decode multibase key."
      Just key -> pure key

    docId :: Did
    docId = Did "example" "123456789abcdefghi"

    jwkId :: Did -> DidUrl
    jwkId did = newDidUrl did & didUrlFragment ?~ "keys-1"

    jwkMethod :: Did -> JWK -> VerificationMethod
    jwkMethod did jwk = VerificationMethod (jwkId did) "JsonWebKey2020" did (PublicKeyJwk jwk)

    multibaseId :: Did -> DidUrl
    multibaseId did = newDidUrl did & didUrlFragment ?~ "keys-2"

    multibaseMethod :: Did -> Multibase -> VerificationMethod
    multibaseMethod did mlt = VerificationMethod (multibaseId did) "Ed25519VerificationKey2020" did (PublicKeyMultibase mlt)

    serviceId :: Did -> DidUrl
    serviceId did = newDidUrl did & didUrlFragment ?~ "linked-domain"

    service :: Did -> Service
    service did = Service (serviceId did) "LinkedDomains" "https://bar.example.com"
