{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TemplateHaskell    #-}
{-# LANGUAGE TypeApplications   #-}

{-|

Module      : SSI.Types.Codec
Description : Utility encoding and decoding functions for text data types
Copyright   : (c) Lando Löper, 2022
License     : Apache License 2.0
Maintainer  : lando.loeper@gmx.net
Stability   : experimental
Portability : unknown

Utility encoding and decoding functions for text data types.

-}
module SSI.Types.Codec
  (
  -- * Working with Text data
    FromText(..)
  , ToText(..)
  , text
  , utf8

  -- * Working with Multibase encoding
  , Multibase(..)
  , multibase
  , base58btc
  , base64url
  , _Base58btc
  , _Base64url
  ) where

import Control.Applicative(Alternative(..))
import Control.Lens (Prism', makePrisms, prism, prism', preview, review)
import Data.Aeson (FromJSON(..), ToJSON(..))
import Data.Bifunctor (Bifunctor(..))
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Text.Strict.Lens (utf8)
import GHC.Generics (Generic)

import qualified Data.Aeson as Json
import qualified Data.ByteString.Base58 as Base58
import qualified Data.ByteString.Base64.URL as Base64.URL
import qualified Data.ByteString.Char8 as BSC

{-|

A type that can be converted from Text, with the possibility of failure.

-}
class FromText a where
  parseText :: Text -> Either Text a

{-|

A type that can be converted to Text.

-}
class ToText a where
  toText :: a -> Text

text :: (FromText a, ToText a) => Prism' Text a
text = prism toText parseText

{-|

A data type defining multibase encodings.

-}
data Multibase
  = Base58btc ByteString
  | Base64url ByteString
  deriving (Show, Eq, Generic)

makePrisms ''Multibase

instance FromJSON Multibase where
  parseJSON = Json.withText "Multibase" $ maybe empty pure . preview multibase . review utf8

instance ToJSON Multibase where
  toJSON = maybe Json.Null Json.String . preview utf8 . review multibase

base58btc :: Prism' ByteString ByteString
base58btc = prism' (Base58.encodeBase58 Base58.bitcoinAlphabet) (Base58.decodeBase58 Base58.bitcoinAlphabet)

base64url :: Prism' ByteString ByteString
base64url = prism Base64.URL.encode (\bs -> first (const bs) (Base64.URL.decode bs))

multibase :: Prism' ByteString Multibase
multibase = prism' encode decode
  where
    encode :: Multibase -> ByteString
    encode (Base58btc bytes) = BSC.cons 'z' $ review base58btc bytes
    encode (Base64url bytes) = BSC.cons 'u' $ review base58btc bytes

    decode :: ByteString -> Maybe Multibase
    decode bs = case BSC.uncons bs of
      Just ('z', base58) -> Base58btc <$> preview base58btc base58
      Just ('u', base64) -> Base64url <$> preview base64url base64
      _ -> Nothing
