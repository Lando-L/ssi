{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TypeApplications   #-}

module SSI.Identity.ResolverSpec
  ( spec
  ) where

import Control.Monad.Except (runExcept)
import Test.Hspec (Spec, context, describe, it, shouldBe)

import SSI.Identity.Did (Did(..), DidDocument, DidDocumentMetadata, newDidDocument, emptyDidDocumentMetadata)
import SSI.Identity.Resolver (Resolver, ResolutionError(..), combineResolvers)

import qualified Data.Map.Strict as Map

spec :: Spec
spec = describe "Resolver" $ do
  describe "combineResolvers" $ do
    context "when given an empty map of resolvers" $
      it "returns an empty resolver" $
        runExcept (combineResolvers Map.empty docId) `shouldBe` Left (DidMethodNotSupported "example")

    context "when given a valid set of resolvers" $
      it "returns a combined resolver that supports multiple DID methods" $
        runExcept (combineResolvers @ResolutionError (Map.singleton "example" resolver) docId) `shouldBe` Right (newDidDocument docId, emptyDidDocumentMetadata)
  where
    docId :: Did
    docId = Did "example" "123456789abcdefghi"

    resolver :: Applicative m => Resolver Did m (DidDocument, DidDocumentMetadata)
    resolver did = pure (newDidDocument did, emptyDidDocumentMetadata)
