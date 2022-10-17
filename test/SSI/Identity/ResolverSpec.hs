{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TypeApplications   #-}

module SSI.Identity.ResolverSpec
  ( spec
  ) where

import Control.Lens (preview, (.~), (?~))
import Control.Monad.Except (runExcept)
import Data.Function ((&))
import Data.Map.Strict (Map)
import Data.Text (Text)
import Test.Hspec (Spec, context, describe, it, shouldBe)

import SSI.Identity.Did (Did(..), DidUrl(..), DidDocument(..), DidDocumentMetadata(..), VerificationMethod(..), VerificationMethodKey(..), newDidUrl, didUrlFragment, newDidDocument, docVerificationMethod, emptyDidDocumentMetadata)
import SSI.Identity.Resolver (Resolver, ResolutionError(..), resolve, dereference)
import SSI.Types.Codec (Multibase, multibase)

import qualified Data.Map.Strict as Map
import qualified Data.Text.Encoding as TE

spec :: Spec
spec = describe "Resolver" $ do
  describe "resolve" $ do
    context "when given an empty map of resolvers" $
      it "returns an empty resolver" $
        runExcept (resolve Map.empty docId) `shouldBe` Left (DidMethodNotSupported "example")

    context "when given a valid set of resolvers" $
      it "returns a combined resolver that supports multiple DID methods" $ do
        mlt <- key
        runExcept (resolve @ResolutionError (state mlt) docId) `shouldBe` Right (doc mlt docId, emptyDidDocumentMetadata)

  describe "dereference" $ do
    context "when given an empty map of resolvers" $
      it "returns an empty dereferencer" $
        runExcept (dereference Map.empty (keyId docId)) `shouldBe` Left (DidMethodNotSupported "example")

    context "when given a valid set of resolvers" $
      it "returns a combined dereferencer that supports multiple DID methods" $ do
        mlt <- key
        runExcept (dereference @ResolutionError (state mlt) (keyId docId)) `shouldBe` Right (keyMethod mlt docId)
  where
    state :: Applicative m => Multibase -> Map Text (Resolver m Did (DidDocument, DidDocumentMetadata))
    state = Map.singleton "example" . resolver

    resolver :: Applicative m => Multibase -> Resolver m Did (DidDocument, DidDocumentMetadata)
    resolver mlt did = pure
      ( doc mlt did
      , emptyDidDocumentMetadata
      )

    doc :: Multibase -> Did -> DidDocument
    doc mlt did = newDidDocument did & docVerificationMethod .~ Map.singleton (keyId did) (keyMethod mlt did)

    docId :: Did
    docId = Did "example" "123456789abcdefghi"

    key :: MonadFail m => m Multibase
    key = case preview multibase (TE.encodeUtf8 "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV") of
      Nothing -> fail "Could not decode multibase string."
      Just x -> pure x

    keyId :: Did -> DidUrl
    keyId did = newDidUrl did & didUrlFragment ?~ "keys-1"

    keyMethod :: Multibase -> Did -> VerificationMethod
    keyMethod mlt did = VerificationMethod (keyId did) "Ed25519VerificationKey2020" did (PublicKeyMultibase mlt)
