{-# LANGUAGE DeriveGeneric          #-}
{-# LANGUAGE DerivingStrategies     #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE KindSignatures         #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE TemplateHaskell        #-}
{-# LANGUAGE UndecidableInstances   #-}

{-|

Module      : SSI.Error
Description : SSI error types and utilities
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

SSI error types and utilities.

-}
module SSI.Error
  (
  -- * Running SSI computations
    Ssi
  , runSsi

  -- * SSI error type and class
  , SsiError(..)
  , AsSsiError(..)
  ) where

import Control.Applicative (Alternative(..))
import Control.Lens (makeClassyPrisms)
import Control.Monad.Except (MonadError(..), ExceptT(..), runExceptT, mapExceptT)
import Control.Monad.IO.Class (MonadIO(..))
import Control.Monad.Reader (MonadReader(..))
import Control.Monad.State (MonadState(..))
import Control.Monad.Trans (MonadTrans(..))
import Crypto.JOSE (MonadRandom(..))
import Data.Functor.Contravariant (Contravariant(..))
import Data.Kind (Type)
import GHC.Generics (Generic)

import SSI.Credential.Proof.SigningKeyStore (AsSigningError(..), SigningError(..))
import SSI.Credential.Proof.VerificationKeyStore (AsVerificationError(..), VerificationError(..))
import SSI.Identity.Resolver (AsResolutionError(..), ResolutionError)

import qualified Crypto.JWT as JWT.Error
import qualified Crypto.JOSE.Error as JOSE.Error

{-|

The ssi monad transformer.

-}
newtype Ssi e (m :: Type -> Type) a = Ssi
  { unSsi :: ExceptT e m a
  } deriving stock (Generic)

-- | Run a ssi computation. 
runSsi :: Ssi e m a -> m (Either e a)
runSsi = runExceptT . unSsi

instance Functor m => Functor (Ssi e m) where
  fmap f = Ssi . fmap f . unSsi
  {-# INLINE fmap #-}

instance Contravariant m => Contravariant (Ssi e m) where
  contramap f = Ssi . contramap f . unSsi
  {-# INLINE contramap #-}

instance Foldable f => Foldable (Ssi e f) where
  foldMap f (Ssi a) = foldMap f a
  {-# INLINE foldMap #-}

instance Traversable t => Traversable (Ssi e t) where
  traverse f (Ssi a) = Ssi <$> traverse f a
  {-# INLINE traverse #-}

instance Monad m => Applicative (Ssi e m) where
  pure = Ssi . pure
  {-# INLINE pure #-}
  (Ssi f) <*> (Ssi v) = Ssi $ f <*> v
  {-# INLINE (<*>) #-}

instance (Monad m, Monoid e) => Alternative (Ssi e m) where
  empty = Ssi empty
  {-# INLINE empty #-}
  (Ssi m) <|> (Ssi n) = Ssi $ m <|> n
  {-# INLINE (<|>) #-}

instance Monad m => Monad (Ssi e m) where
  (Ssi run) >>= f = Ssi $ run >>= unSsi . f
  {-# INLINE (>>=) #-}

instance MonadTrans (Ssi e) where
  lift = Ssi . lift
  {-# INLINE lift #-}

instance MonadIO m => MonadIO (Ssi e m) where
  liftIO = Ssi . liftIO
  {-# INLINE liftIO #-}

instance Monad m => MonadError e (Ssi e m) where
  throwError = Ssi . throwError
  {-# INLINE throwError #-}
  catchError (Ssi run) handle = Ssi (catchError run (unSsi . handle))
  {-# INLINE catchError #-}

instance MonadReader r m => MonadReader r (Ssi e m) where
  ask = lift ask
  {-# INLINE ask #-}
  local f = Ssi . mapExceptT (local f) . unSsi
  {-# INLINE local #-}
  reader = lift . reader
  {-# INLINE reader #-}

instance MonadRandom m => MonadRandom (Ssi e m) where
  getRandomBytes = lift . getRandomBytes
  {-# INLINE getRandomBytes #-}

instance MonadState s m => MonadState s (Ssi e m) where
  get = lift get
  {-# INLINE get #-}
  put = lift . put
  {-# INLINE put #-}
  state = lift . state
  {-# INLINE state #-}

{-|

All errors that may occur.

-}
data SsiError
  = CredentialSigningError SigningError
  -- ^ An error occuring during credential signing.
  | CredentialVerificationError VerificationError
  -- ^ An error occuring during credential verification.
  | IdentityResolutionError ResolutionError
  -- ^ An error occuring during identities resolution.
  | JWTError JWT.Error.JWTError
  -- ^ Various jose library error cases.
  deriving stock (Show, Eq)

makeClassyPrisms ''SsiError

instance JOSE.Error.AsError SsiError where
  _Error = _JWTError . JOSE.Error._Error

instance JWT.Error.AsJWTError SsiError where
  _JWTError = _JWTError

instance AsResolutionError SsiError where
  _ResolutionError = _IdentityResolutionError

instance AsSigningError SsiError where
  _SigningError = _CredentialSigningError

instance AsVerificationError SsiError where
  _VerificationError = _CredentialVerificationError
