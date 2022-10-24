{-# LANGUAGE TemplateHaskell        #-}

{-|

Module      : SSI.Credential.Proof.VerificationKeyStore
Description : Verification key store class and error types
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Verification key store class and error types.

-}
module SSI.Credential.Proof.VerificationKeyStore
  ( VerificationKeyStore(..)
  , VerificationError(..)
  , AsVerificationError(..)
  ) where

import Control.Lens (makeClassyPrisms)
import Crypto.JOSE.JWK.Store (VerificationKeyStore(..))

{-|

Errors that may occur during credential verification.

-}
data VerificationError = VerificationJWKNotFound
  deriving (Show, Eq)

makeClassyPrisms ''VerificationError
