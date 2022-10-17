{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE TemplateHaskell        #-}

{-|

Module      : SSI.Identity.Resolver
Description : Generic resolvers for DID resolution and DID URL dereferencing
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Generic resolvers for DID resolution and DID URL dereferencing.

For example, the following instance leverages a static in memory store to resolve DIDs:

@
import SSI.Identity.Did
import SSI.Identity.Resolver

inMemoryResolver => Map Did (DidDocument, DidDocumentMetadata) -> Resolver Maybe Did (DidDocument, DidDocumentMetadata)
inMemoryResolver store did = lookup did store
@

You can combine Resolvers of different DID methods like this:

@
import SSI.Identity.Did
import SSI.Identity.Resolver

resolver :: MonadError ResolutionError m => Resolver m Did (DidDocument, DidDocumentMetadata)
resolver = resolve $ fromList
  [ ("example", exampleDidResolver)
  , ("key", keyDidResolver)
  , ("peer", peerDidResolver)
  ]
@

You can also combine Resolvers to dereference Verification Methods within DID documents:

@
import SSI.Identity.Did
import SSI.Identity.Resolver

dereferencer :: MonadError ResolutionError m => Resolver m DidUrl VerificationMethod
dereferencer = dereference $ fromList
  [ ("example", exampleDidResolver)
  , ("key", keyDidResolver)
  , ("peer", peerDidResolver)
  ]
@

-}
module SSI.Identity.Resolver
  ( 
  -- * Resolvers
    Resolver
  , HasResolver(..)

  -- * Combining Resolvers
  , resolve
  , dereference

  -- * Resolution Errors
  , ResolutionError(..)
  , AsResolutionError(..)
  ) where

import Control.Lens (Lens', ix, makeClassyPrisms, review, preview, (^.))
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except (MonadError(..))
import Data.Map.Strict (Map)
import Data.Text (Text)

import SSI.Identity.Did (Did, HasDid(..), DidUrl, DidDocument, DidDocumentMetadata, VerificationMethod, docVerificationMethod)
import SSI.Types.Codec (text)

import qualified Data.Map.Strict as Map
import qualified Data.Text as T

{-|

A Resolver defines a generic type for DID resolution and DID dereferencing.

-}
type Resolver m a b = a -> m b

class HasResolver m a b c where
  resolver :: Lens' c (Resolver m a b)

{-|

All resolution errors that may occur during DID resolution or DID dereferencing.

-}
data ResolutionError
  = DidInvalid Text
  -- ^ An identifier with invalid DID syntax.
  | DidNotFound Text
  -- ^ An identifier that could not be resolved.
  | DidMethodNotSupported Text
  -- ^ An identifier with an unsupported DID method.
  deriving (Eq)

makeClassyPrisms ''ResolutionError

instance Show ResolutionError where
  show (DidInvalid _did) = "The provided did '" <> T.unpack _did <> "' is not valid."
  show (DidNotFound _did) = "The provided did '" <> T.unpack _did <> "' was not found."
  show (DidMethodNotSupported method) = "The provided did method '" <> T.unpack method <> "' is not supported."

-- | Combine a set of DID method specific resolvers to a single resolver supporting all included DID methods. 
resolve
  :: (MonadError e m, AsResolutionError e)
  => Map Text (Resolver m Did (DidDocument, DidDocumentMetadata))
  -- ^ The mapping from DID methods to resolvers.
  -> Resolver m Did (DidDocument, DidDocumentMetadata)
  -- ^ The combined resolver.
resolve resolvers _did = case Map.lookup (_did ^. didMethod) resolvers of
  Nothing -> throwing _DidMethodNotSupported $ _did ^. didMethod
  Just f -> f _did

-- | Combine a set of DID method specific resolvers to a single dereferencer supporting all included DID methods. 
dereference
  :: (MonadError e m, AsResolutionError e)
  => Map Text (Resolver m Did (DidDocument, DidDocumentMetadata))
  -- ^ The mapping from DID methods to resolvers.
  -> Resolver m DidUrl VerificationMethod
  -- ^ The combined dereferencer.
dereference resolvers url = case Map.lookup method resolvers of
  Nothing -> notSupported
  Just f -> f (url ^. did) >>= maybe notFound pure . verification . fst
  where
    method :: Text
    method = url ^. (did . didMethod)

    verification :: DidDocument -> Maybe VerificationMethod
    verification = preview (docVerificationMethod . ix url)

    notSupported :: (MonadError e m, AsResolutionError e) => m VerificationMethod
    notSupported = throwing _DidMethodNotSupported method

    notFound :: (MonadError e m, AsResolutionError e) => m VerificationMethod
    notFound = throwing _DidNotFound $ review text url
