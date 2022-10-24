{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE TemplateHaskell        #-}
{-# LANGUAGE UndecidableInstances   #-}

{-|

Module      : SSI.Identity.Resolver
Description : Resolver type for DID resolution
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Resolver type for DID resolution.

-}
module SSI.Identity.Resolver
  ( 
  -- * DID resolution
  -- $didResolution

  -- * The Resolver type
    Resolver

  -- * Resolver operations
  , combineResolvers

  -- * Resolution Errors
  , ResolutionError(..)
  , AsResolutionError(..)
  ) where

import Control.Lens (makeClassyPrisms, (^.))
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except (MonadError(..))
import Data.Map.Strict (Map)
import Data.Text (Text)

import SSI.Identity.Did (HasDid(..), DidDocument, DidDocumentMetadata)

import qualified Data.Map.Strict as Map
import qualified Data.Text as T

-- $didResolution
-- 
-- An in memory DID resolver might be implemented like this:
-- 
-- @
-- import Data.Map.Strict
-- 
-- import SSI.Identity.Did
-- import SSI.Identity.Resolver
-- 
-- import qualified Data.Map.Strict as Map
-- 
-- inMemoryResolver
--   :: Map Did (DidDocument, DidDocumentMetadata)
--   -> Resolver Did Maybe (DidDocument, DidDocumentMetadata)
-- inMemoryResolver = flip Map.lookup
-- @
-- 
-- Resolvers for different DID methods may be combined like this:
-- 
-- @
-- {-# LANGUAGE FlexibleContexts   #-}
-- {-# LANGUAGE OverloadedStrings  #-}
-- 
-- import Control.Monad.Except
-- 
-- import SSI.Identity.Did
-- import SSI.Identity.Resolver
-- 
-- import qualified Data.Map.Strict as Map
-- 
-- resolver
--   :: MonadError ResolutionError m
--   => Resolver Did m (DidDocument, DidDocumentMetadata)
--   -> Resolver Did m (DidDocument, DidDocumentMetadata)
--   -> Resolver Did m (DidDocument, DidDocumentMetadata)
--   -> Resolver Did m (DidDocument, DidDocumentMetadata)
-- resolver example key peer = combineResolvers $ Map.fromList
--   [ ("example", example)
--   , ("key", key)
--   , ("peer", peer)
--   ]
-- @

{-|

The parameterizable resolver type.

-}
type Resolver a m b = a -> m b

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
combineResolvers
  :: (MonadError e m, AsResolutionError e, HasDid a)
  => Map Text (Resolver a m (DidDocument, DidDocumentMetadata))
  -- ^ The mapping from DID methods to resolvers.
  -> Resolver a m (DidDocument, DidDocumentMetadata)
  -- ^ The combined resolver.
combineResolvers resolvers _did = case Map.lookup (_did ^. didMethod) resolvers of
  Nothing -> throwing _DidMethodNotSupported $ _did ^. didMethod
  Just resolve -> resolve _did
