{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE QuasiQuotes        #-}
{-# LANGUAGE TypeApplications   #-}

module SSI.Credential.VerifiableCredentialSpec
  ( spec
  ) where

import Control.Lens (review, reviews, (?~))
import Control.Monad.Except (MonadError(..))
import Control.Monad.Time (MonadTime(..))
import Crypto.JOSE.Error (Error(..))
import Crypto.JOSE.JWK (Crv(..), JWK, KeyMaterialGenParam(..))
import Crypto.JWT (JWTError(..))
import Data.Aeson (Value(..))
import Data.Aeson.QQ.Simple (aesonQQ)
import Data.Function ((&))
import Data.Time.Clock (UTCTime(..))
import Test.Hspec (Spec, context, describe, it, shouldReturn)

import SSI.Credential.VerifiableCredential (issue, present, verifyCredential, verifyPresentation)
import SSI.Identity.Did (Did(..), DidUrl(..), VerificationMethod (..), VerificationMethodKey(..), newDidUrl, didUrlFragment)
import SSI.Identity.Resolver (AsResolutionError(..), ResolutionError(..), Resolver)
import SSI.Types.Codec (text)
import SSI.Types.Error (SsiError(..))

import qualified Crypto.JOSE.JWK as Jwk
import qualified Crypto.JWT as Jwt
import qualified Data.Time.Clock as Time

spec :: Spec
spec = do
  vcSpec
  vpSpec

vcSpec :: Spec
vcSpec = describe "VerifiableCredentials" $
  describe "issuance and verification" $ do
    context "when given an unresolvable reference" $
      it "fails the validation process" $ do
        jwk <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              issue @SsiError jwk (ref issuer) "1" subject degree now now (Just (future now))
                >>= verifyCredential @SsiError emptyResolver subject
            )
          )
          (Left (IdentityError (DidNotFound (review text (ref issuer)))))

    context "when given a wrong audience" $
      it "fails the validation process" $ do
        jwk <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              issue @SsiError jwk (ref issuer) "1" subject degree now now (Just (future now))
                >>= verifyCredential @SsiError (staticResolver issuer jwk) issuer
            )
          )
          (Left (CredentialError JWTNotInAudience))

    context "when given valid parameters" $
      it "returns the validated credentials" $ do
        jwk <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              issue @SsiError jwk (ref issuer) "1" subject degree now now (Just (future now))
                >>= verifyCredential @SsiError (staticResolver issuer jwk) subject
            )
          )
          (Right degree)

vpSpec :: Spec
vpSpec = describe "VerifiablePresentation" $
  describe "presentation and verification" $ do
    context "when given a wrong nonce" $
      it "fails the validation process" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              sequence
                [ issue @SsiError issuerKey (ref issuer) "1" subject degree now now (Just (future now))
                , issue @SsiError issuerKey (ref issuer) "2" subject food now now (Just (future now))
                ]
                >>= present @SsiError subjectKey subject "1" verifier now now (Just (future now)) "secret"
                >>= verifyPresentation @SsiError "wrong" (staticResolver issuer issuerKey) verifier
            )
          )
          (Left (CredentialError (JWSError NoUsableKeys)))

    context "when given an unresolvable reference" $
      it "fails the validation process" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              sequence
                [ issue @SsiError issuerKey (ref issuer) "1" subject degree now now (Just (future now))
                , issue @SsiError issuerKey (ref issuer) "2" subject food now now (Just (future now))
                ]
                >>= present @SsiError subjectKey subject "1" verifier now now (Just (future now)) "secret"
                >>= verifyPresentation @SsiError "secret" emptyResolver verifier
            )
          )
          (Left (IdentityError (DidNotFound (review text (ref issuer)))))
    
    context "when given a wrong audience" $
      it "fails the validation process" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              sequence
                [ issue @SsiError issuerKey (ref issuer) "1" subject degree now now (Just (future now))
                , issue @SsiError issuerKey (ref issuer) "2" subject food now now (Just (future now))
                ]
                >>= present @SsiError subjectKey subject "1" verifier now now (Just (future now)) "secret"
                >>= verifyPresentation @SsiError "secret" (staticResolver issuer issuerKey) issuer
            )
          )
          (Left (CredentialError JWTNotInAudience))
    
    context "when given valid parameters" $
      it "returns the validated credentials" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            Jwt.runJOSE (
              sequence
                [ issue @SsiError issuerKey (ref issuer) "1" subject degree now now (Just (future now))
                , issue @SsiError issuerKey (ref issuer) "2" subject food now now (Just (future now))
                ]
                >>= present @SsiError subjectKey subject "1" verifier now now (Just (future now)) "secret"
                >>= verifyPresentation @SsiError "secret" (staticResolver issuer issuerKey) verifier
            )
          )
          (Right [degree, food])

issuer :: Did
issuer = Did "example" "issuer"

subject :: Did
subject = Did "example" "subject"

verifier :: Did
verifier = Did "example" "verifier"

degree :: Value
degree = [aesonQQ|{"type":"BachelorDegree", "name":"Bachelor of Science"}|]

food :: Value
food = [aesonQQ|{"type": "FavoriteFood", "name": "Papaya"}|]

staticResolver :: Applicative m => Did -> JWK -> Resolver m DidUrl VerificationMethod
staticResolver did jwk = const $ pure $ VerificationMethod (ref did) "JsonWebKey2020" did (PublicKeyJwk jwk)

emptyResolver :: (MonadError e m, AsResolutionError e) => Resolver m DidUrl VerificationMethod
emptyResolver = reviews (_DidNotFound . text) throwError

ref :: Did -> DidUrl
ref did = newDidUrl did & didUrlFragment ?~ "keys-1"

future :: UTCTime -> UTCTime
future = Time.addUTCTime (Time.secondsToNominalDiffTime 1000)
