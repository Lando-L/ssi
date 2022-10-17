{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE TemplateHaskell    #-}

{-|

Module      : SSI.Types.Error
Description : SSI error types and utilities
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

SSI error types and utilities.

-}

module SSI.Types.Error
  ( SsiError(..)
  , AsSsiError(..)
  ) where

import Control.Lens (makeClassyPrisms)
import Crypto.JWT (AsJWTError(..), JWTError)
import Crypto.JOSE.Error (AsError(..))

import SSI.Identity.Resolver (AsResolutionError(..), ResolutionError)

{-|

All errors that may occur.

-}
data SsiError
  = CredentialError JWTError
  -- ^ An error occuring while working with credentials.
  | IdentityError ResolutionError
  -- ^ An error occuring while working with identities.
  deriving stock (Show, Eq)

makeClassyPrisms ''SsiError

instance AsError SsiError where
  _Error = _CredentialError . _Error

instance AsJWTError SsiError where
  _JWTError = _CredentialError

instance AsResolutionError SsiError where
  _ResolutionError = _IdentityError
