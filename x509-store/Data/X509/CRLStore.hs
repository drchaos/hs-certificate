{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.X509.CRLStore
    ( CRLStore(..)
    , CRLStorePure
    , StoredCRL
    , signedCRL
    , newMemoryStore
    , newFileStore
    , newFileStoreWithManager
    , loadStore
    -- * Queries
    , lookupStore
    , hasSerial
    ) 
      where

import Data.BloomFilter.Easy  (Bloom, easyList)
import Data.ByteString.Base58
import Data.ByteString.Lazy   (toStrict)
import Data.Default.Class
import Data.Foldable          (asum)
import Data.IORef             (IORef, newIORef, readIORef, atomicModifyIORef')
import Data.Map.Strict        (Map)
import Data.Maybe             (mapMaybe, catMaybes)
import Data.X509
import Control.Applicative    ((<$>))
import Control.Exception      (Exception, throwIO, throw, IOException, catch)
import Control.Monad          (forM, forM_)
import Network.URI            (normalizeCase)
import Network.HTTP.Client    (Manager, parseRequest, Response (..),
                               httpLbs, newManager, defaultManagerSettings)
import System.Directory       (listDirectory)
import System.FilePath        ((</>))
import Time.System            (dateCurrent)

import qualified Data.BloomFilter.Easy as BF
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.Map.Strict       as Map

type CRLStorePure = Map String StoredCRL
type CRLStorePureRef = IORef CRLStorePure

data CRLStoreError = CRLDecodeError { crlURI :: String, crlError :: String }
                   | CRLExtError String
  deriving Show

instance Exception CRLStoreError

data CRLStore = CRLStore { getStore :: IO CRLStorePure
                         , fetchCRL :: DistributionPoint -> IO ()
                         }
               
instance Default CRLStore where
    def = CRLStore (return mempty) (const $ return ())

data StoredCRL = StoredCRL
               { signedCRL      :: !SignedCRL
               , revokedSerials :: !(Bloom Integer)
               }

hasSerial :: StoredCRL -> Certificate -> Bool
hasSerial StoredCRL{..} cert = certSerial cert `BF.elem` revokedSerials

mkStoredCRL :: SignedCRL -> StoredCRL
mkStoredCRL signedCRL = StoredCRL {..}
  where revokedSerials = easyList 0.01
                       $ fmap revokedSerialNumber
                       $ crlRevokedCertificates
                       $ getCRL signedCRL

newMemoryStore :: CRLStorePure -> IO CRLStore
newMemoryStore m =
  newManager defaultManagerSettings >>= newMemoryStoreWithManager m

newMemoryStoreWithManager :: CRLStorePure -> Manager -> IO CRLStore
newMemoryStoreWithManager m manager = do
  ref <- newIORef m
  return $ CRLStore { getStore = readIORef ref
                    , fetchCRL = fetchAndSave noSaving manager ref
                    }

noSaving :: String -> B8.ByteString -> IO ()
noSaving = const $ const $ return ()

newFileStore :: FilePath -> IO CRLStore
newFileStore crlsPath =
  newManager defaultManagerSettings >>= newFileStoreWithManager crlsPath

newFileStoreWithManager :: FilePath -> Manager -> IO CRLStore
newFileStoreWithManager crlsPath manager = do
  ref <- newIORef =<< loadStore crlsPath
  return $ CRLStore { getStore = readIORef ref
                    , fetchCRL = fetchAndSave (saveTo crlsPath) manager ref
                    }

uriToFile :: String -> String
uriToFile = B8.unpack . encodeBase58 bitcoinAlphabet . B8.pack

fileToURI :: String -> Maybe String
fileToURI = fmap B8.unpack . decodeBase58 bitcoinAlphabet . B8.pack

loadStore :: FilePath -> IO CRLStorePure
loadStore cacheDir = do
  files <- listDirectory cacheDir `catch` emptyDir
  let storedCRLs = mapMaybe (\ f -> (,cacheDir </> f) <$> fileToURI f) files
  readCRLs <- forM storedCRLs $ \ (uri,path) -> do
    (either (const Nothing) (Just . (uri,).mkStoredCRL) . decodeSignedCRL <$> B.readFile path) `catch` skipIOError
  return $ Map.fromList $ catMaybes readCRLs
  where skipIOError (_ :: IOException) = return Nothing
        emptyDir    (_ :: IOException) = return []
  

saveTo :: FilePath -> String -> B8.ByteString -> IO ()
saveTo crlsPath uri bs = do
                print path
                B.writeFile path bs
  where path = crlsPath </> uriToFile uri

fetchAndSave :: (String -> B8.ByteString -> IO ()) -> Manager -> CRLStorePureRef -> DistributionPoint -> IO ()
fetchAndSave saveCRL manager mapRef dp = do
  now <- dateCurrent
  m <- readIORef mapRef
  case lookupStore dp m of
    Just cachedCRL
      | Just t <- crlNextUpdate $ getCRL $ signedCRL cachedCRL
      , now < t -> return ()
    _ -> do
      case getURIs <$> distributionPointName dp of
            Nothing -> return ()
            Just uris -> do
              forM_ uris $ \ uri -> do
                request <- parseRequest uri
                f <- toStrict . responseBody <$> httpLbs request manager
                sCrl <- either (throwIO . CRLDecodeError uri) return $ decodeSignedCRL f
                saveCRL uri f
                atomicModifyIORef' mapRef $ \ m' -> ( Map.insert uri (mkStoredCRL sCrl) m' , ())

lookupStore :: DistributionPoint -> CRLStorePure -> Maybe StoredCRL
lookupStore dp m
  | Just dpn <- distributionPointName dp 
  , names <- getURIs dpn = asum $ fmap (`Map.lookup` m) names
  | otherwise = throw $ CRLExtError "DP has no name"

getURIs :: DistributionPointName -> [String]
getURIs (DistributionPointFullName names) 
  | not $ null uris = uris
  | otherwise       = throw $ CRLExtError "DP has no URI to fetch CRL"
  where uris = mapMaybe getURI names
getURIs _ = throw $ CRLExtError "Distribution point relative name is not implemented"

getURI :: AltName -> Maybe String
getURI (AltNameURI s) = Just $ normalizeCase s
getURI _ = Nothing


