{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE KindSignatures         #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE TemplateHaskell        #-}

{-|

Module      : SSI.Credential.Proof.SigningKeyStore
Description : Signing key store class and error types
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Signing key store class and error types.

-}
module SSI.Credential.Proof.SigningKeyStore
  ( SigningKeyStore(..)
  , SigningError(..)
  , AsSigningError(..)
  ) where

import Control.Lens (makeClassyPrisms)
import Crypto.JOSE.JWK (JWK)
import Data.Kind (Type)

{-|

Signing key lookup.

-}
class SigningKeyStore a (m :: Type -> Type) where
  getSigningKey :: a -> m JWK

instance Applicative m => SigningKeyStore JWK m where
  getSigningKey = pure

{-|

Errors that may occur during credential signing.

-}
data SigningError = SigningJWKNotFound
  deriving (Show, Eq)

makeClassyPrisms ''SigningError
