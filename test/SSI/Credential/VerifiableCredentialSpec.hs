{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE QuasiQuotes        #-}
{-# LANGUAGE TypeApplications   #-}

module SSI.Credential.VerifiableCredentialSpec
  ( spec
  ) where

import Control.Lens (review, reviews, (?~))
import Control.Monad.Except (MonadError (..))
import Control.Monad.Time (MonadTime(..))
import Crypto.JOSE.JWK (Crv(..), KeyMaterialGenParam(..))
import Crypto.JWT (JWK, JWTError(..))
import Data.Aeson (Value)
import Data.Aeson.QQ.Simple (aesonQQ)
import Data.Function ((&))
import Data.Text (Text)
import Data.Time (UTCTime)
import Test.Hspec (Spec, context, describe, it, shouldReturn)

import SSI.Error (SsiError(..), runSsi)
import SSI.Identity.Did (Did (..), DidUrl, VerificationMethod (..), VerificationMethodKey (..), newDidUrl, didUrlFragment)
import SSI.Identity.Resolver (Resolver, ResolutionError(..), AsResolutionError(..))
import SSI.Credential.VerifiableCredential (VerifiableCredential(..), VerifiablePresentation(..))
import SSI.Credential.Proof.Jwt (signCredential, verifyCredential, signPresentation, verifyPresentation)
import SSI.Credential.Proof.VerificationKeyStore (VerificationError(..))
import SSI.Types.Codec (text)

import qualified Crypto.JOSE.JWK as Jwk

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
            runSsi (
              signCredential jwk (ref issuer) (credential "1" now degree)
                >>= verifyCredential emptyResolver subject
            )
          )
          (Left (IdentityResolutionError (DidNotFound (review text (ref issuer)))))

    context "when given a wrong audience" $
      it "fails the validation process" $ do
        jwk <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            runSsi (
              signCredential jwk (ref issuer) (credential "1" now degree)
                >>= verifyCredential (staticResolver issuer jwk) issuer
            )
          )
          (Left (JWTError JWTNotInAudience))

    context "when given valid parameters" $
      it "returns the validated credentials" $ do
        jwk <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            runSsi (
              signCredential @SsiError jwk (ref issuer) (credential "1" now degree)
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
            runSsi (
              sequence
                [ signCredential issuerKey (ref issuer) (credential "1" now degree)
                , signCredential issuerKey (ref issuer) (credential "2" now food)
                ]
                >>= signPresentation subjectKey subject verifier "nonce" . presentation now
                >>= verifyPresentation "wrong" (staticResolver issuer issuerKey) verifier
            )
          )
          (Left (CredentialVerificationError VerificationJWKNotFound))

    context "when given an unresolvable reference" $
      it "fails the validation process" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            runSsi (
              sequence
                [ signCredential issuerKey (ref issuer) (credential "1" now degree)
                , signCredential issuerKey (ref issuer) (credential "2" now food)
                ]
                >>= signPresentation subjectKey subject verifier "nonce" . presentation now
                >>= verifyPresentation "nonce" emptyResolver verifier
            )
          )
          (Left (IdentityResolutionError (DidNotFound (review text (ref issuer)))))
    
    context "when given a wrong audience" $
      it "fails the validation process" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            runSsi (
              sequence
                [ signCredential issuerKey (ref issuer) (credential "1" now degree)
                , signCredential issuerKey (ref issuer) (credential "2" now food)
                ]
                >>= signPresentation subjectKey subject subject "nonce" . presentation now
                >>= verifyPresentation "nonce" (staticResolver issuer issuerKey) verifier
            )
          )
          (Left (JWTError JWTNotInAudience))
    
    context "when given valid parameters" $
      it "returns the validated credentials" $ do
        issuerKey <- Jwk.genJWK (ECGenParam P_256)
        subjectKey <- Jwk.genJWK (ECGenParam P_256)
        now <- currentTime
        shouldReturn
          (
            runSsi (
              sequence
                [ signCredential @SsiError issuerKey (ref issuer) (credential "1" now degree)
                , signCredential @SsiError issuerKey (ref issuer) (credential "2" now food)
                ]
                >>= signPresentation @SsiError subjectKey subject verifier "nonce" . presentation now
                >>= verifyPresentation @SsiError "nonce" (staticResolver issuer issuerKey) verifier
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

credential :: Text -> UTCTime -> Value -> VerifiableCredential
credential _id now = VerifiableCredential _id issuer now now Nothing subject

presentation :: UTCTime -> [Text] -> VerifiablePresentation
presentation now = VerifiablePresentation "1" subject now now Nothing

staticResolver :: Applicative m => Did -> JWK -> Resolver DidUrl m VerificationMethod
staticResolver did jwk = const $ pure $ VerificationMethod (ref did) "JsonWebKey2020" did (PublicKeyJwk jwk)

emptyResolver :: (MonadError e m, AsResolutionError e) => Resolver DidUrl m VerificationMethod
emptyResolver = reviews (_DidNotFound . text) throwError

ref :: Did -> DidUrl
ref did = newDidUrl did & didUrlFragment ?~ "keys-1"
