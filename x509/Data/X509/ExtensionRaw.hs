-- |
-- Module      : Data.X509.ExtensionRaw
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension marshalling
--
module Data.X509.ExtensionRaw
    ( ExtensionRaw(..)
    , Extensions(..)
    ) where

import Control.Applicative
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.X509.Internal

data ExtensionRaw = ExtensionRaw
    { extRawOID      :: OID
    , extRawCritical :: Bool
    , extRawASN1     :: [ASN1]
    } deriving (Show,Eq)

newtype Extensions = Extensions (Maybe [ExtensionRaw])
    deriving (Show,Eq)

instance ASN1Object Extensions where
    toASN1 exts = \xs -> encodeExts exts ++ xs
    fromASN1 = runParseASN1State parseExtensions

instance ASN1Object ExtensionRaw where
    toASN1 extraw = \xs -> encodeExt extraw ++ xs
    fromASN1 (Start Sequence:OID oid:xs) =
        case xs of
            Boolean b:OctetString obj:End Sequence:xs2 -> extractExt b obj xs2
            OctetString obj:End Sequence:xs2           -> extractExt False obj xs2
            _                                          -> Left ("fromASN1: X509.ExtensionRaw: unknown format:" ++ show xs)
      where
        extractExt critical bs remainingStream =
            case decodeASN1' BER bs of
                Left err -> Left ("fromASN1: X509.ExtensionRaw: OID=" ++ show oid ++
                                  ": cannot decode data: " ++ show err)
                Right r  -> Right (ExtensionRaw oid critical r, remainingStream)
    fromASN1 l                                      =
        Left ("fromASN1: X509.ExtensionRaw: unknown format:" ++ show l)


parseExtensions :: ParseASN1 Extensions
parseExtensions = Extensions <$> (
    onNextContainerMaybe (Container Context 3) $
        onNextContainer Sequence (getMany getObject)
    )
{-
  where getSequences = do
            n <- hasNext
            if n
                then getNextContainer Sequence >>= \sq -> liftM (sq :) getSequences
                else return []
        extractExtension [OID oid,Boolean b,OctetString obj] =
            case decodeASN1' BER obj of
                Left _  -> Nothing
                Right r -> Just (oid, b, r)
        extractExtension [OID oid,OctetString obj]              =
            case decodeASN1' BER obj of
                Left _  -> Nothing
                Right r -> Just (oid, False, r)
        extractExtension _                                      =
            Nothing
-}

encodeExts :: Extensions -> [ASN1]
encodeExts (Extensions Nothing)  = []
encodeExts (Extensions (Just l)) = asn1Container (Container Context 3) $ concatMap encodeExt l

encodeExt :: ExtensionRaw -> [ASN1]
encodeExt (ExtensionRaw oid critical asn1) =
    let bs = encodeASN1' DER asn1
     in asn1Container Sequence ([OID oid] ++ (if critical then [Boolean True] else []) ++ [OctetString bs])
