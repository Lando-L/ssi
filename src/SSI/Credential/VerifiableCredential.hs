{-# LANGUAGE DeriveAnyClass             #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}

{-|

Module      : SSI.Credential.VerifiableCredential
Description : Verifiable Credentials (VCs) v1.1 implementation
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Verifiable Credentials (VCs) v1.1 implementation.

A verifiable credential can represent all of the same information that a physical credential represents.
The addition of technologies, such as digital signatures, makes verifiable credentials more tamper-evident
and more trustworthy than their physical counterparts.

-}
module SSI.Credential.VerifiableCredential
  (
  -- * Verifiable Credential
    VerifiableCredential(..)
  -- ** Lenses
  , vcId
  , vcIssuer
  , vcIssued
  , vcValidFrom
  , vcValidUntil
  , vcSubject
  , vcCredentials

  -- * Verifiable Presentation
  , VerifiablePresentation(..)
  -- ** Lenses
  , vpId
  , vpHolder
  , vpIssued
  , vpValidFrom
  , vpValidUntil
  , vpCredentials
  ) where

import Control.Lens (makeLenses)
import Data.Aeson (Value(..))
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

import SSI.Identity.Did (Did)

{-|

Verifiable Credential type.

-}
data VerifiableCredential = VerifiableCredential
  { _vcId :: !Text
  , _vcIssuer :: !Did
  , _vcIssued :: !UTCTime
  , _vcValidFrom :: !UTCTime
  , _vcValidUntil :: !(Maybe UTCTime)
  , _vcSubject :: !Did
  , _vcCredentials :: !Value
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerifiableCredential

{-|

Verifiable Presentation type.

-}
data VerifiablePresentation = VerifiablePresentation
  { _vpId :: !Text
  , _vpHolder :: !Did
  , _vpIssued :: !UTCTime
  , _vpValidFrom :: !UTCTime
  , _vpValidUntil :: !(Maybe UTCTime)
  , _vpCredentials :: ![Text]
  } deriving stock (Show, Eq, Generic)

makeLenses ''VerifiablePresentation
