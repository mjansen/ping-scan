module PingScan
       ( fetchMACs
       , Entry (..)
       , NetworkInfo (..)
       , Command
       , Machine
       , Login
       , IPv4Subnet
       , ssh
       , scan
       , scanCached
       , scanAll
       , scanAllCached
       ) where

import System.Environment
import System.Exit
import HSH

import Control.Applicative
import Control.Concurrent.Async

import Data.Traversable (Traversable)

import Data.Maybe (catMaybes, listToMaybe)
-- import Data.List (isSuffixOf, isPrefixOf, isInfixOf)

import Text.Printf

import Text.XML.HaXml.Parse (xmlParse)
import Text.XML.HaXml.Util (docContent)
import Text.XML.HaXml.Posn (Posn, noPos)
import Text.XML.HaXml.Types 
import Text.XML.HaXml.Combinators

import Data.Char

readxml fName = do
  dcontent <- readFile fName
  let doc = xmlParse fName dcontent :: Document Posn
      top = docContent noPos doc
  return top

extractHosts :: Content i -> [Content i]
extractHosts = filter isUp
             . concatMap (tag "host") 
             . concatMap children 
             . tag "nmaprun"
             
-- as shown here, xml is rubbish, or maybe my parsing is rubbish:

isUp :: Content i -> Bool
isUp = not . null
     . ifCountIs 1
     . concatMap (attrval (N "state", AttValue [Left "up"]))
     . ifCountIs 1
     . concatMap (tag "status")
     . concatMap children
     . ifCountIs 1
     . tag "host"
     
ifCountIs :: Int -> [Content i] -> [Content i]
ifCountIs n cs = if length cs == n then cs else []

fetchMACs fName = process <$> readxml fName
  where
    process = catMaybes . map mkEntry . extractHosts

main = putStr . unlines . map showEntry . concat =<< mapM fetchMACs =<< getArgs
  
data Entry = Entry
  { e_ipAddress  :: String
  , e_macAddress :: String
  } deriving (Eq, Ord, Show, Read)

mkEntry :: Content i -> Maybe Entry
mkEntry c =
  let extractAddr e = case e of
        CElem (Elem (N "address") as _) _ ->
          case lookup (N "addr") as of
            Nothing -> Nothing
            Just (AttValue [Left a]) -> Just a
        _ -> Nothing
      addrElementA = id
                   . ifCountIs 1
                   . concatMap (attrval (N "addrtype", AttValue [Left "ipv4"]))
                   . concatMap (tag "address")
                   . concatMap children 
                   . ifCountIs 1 
                   . tag "host"
                   $ c
      addrElementM = id
                   . ifCountIs 1
                   . concatMap (attrval (N "addrtype", AttValue [Left "mac"]))
                   . concatMap (tag "address")
                   . concatMap children 
                   . ifCountIs 1 
                   . tag "host"
                   $ c
      ipAddr  =                  extractAddr =<< listToMaybe addrElementA
      macAddr = map toLower <$> (extractAddr =<< listToMaybe addrElementM)
  in Entry <$> ipAddr <*> macAddr
       
showEntry :: Entry -> String
showEntry (Entry addr macAddr) = printf "%-16s %17s" addr macAddr

------------------------------------------------------------------------

-- definition of where to find some networks:

type Command    = String
type Machine    = String
type Login      = String
type IPv4Subnet = String

data NetworkInfo = NetworkInfo
  { ni_name       :: String
  , ni_subnet     :: IPv4Subnet
  , ni_nmap_proxy :: (Machine, Login)
  }

ssh :: Command -> (Machine, Login) -> IO String
ssh cmd (machine, login) = do
  (output, action) <- run ("ssh", [ "-anxT"
                                  , "-o", "ConnectTimeout=5"
                                  , "-o", "StrictHostKeyChecking=no"
                                  , "-l", login, machine
                                  , cmd ]) :: IO (String, IO (String, ExitCode))
  if length output == -1
    then print "error"
    else return ()
  (commandStr, exitCode) <- action
  case exitCode of
    ExitSuccess -> return output
    c           -> printf "error: %s: %s\n" (show c) commandStr >> return ""

nmapCommand :: IPv4Subnet -> Command
nmapCommand = printf "nmap -sP -PE -oX - %s"

scan :: NetworkInfo -> IO [Entry]
scan (NetworkInfo name subnet proxy) = do
  let fName = name ++ ".xml"
  writeFile fName =<< ssh (nmapCommand subnet) proxy
  fetchMACs fName

scanCached :: NetworkInfo -> IO [Entry]
scanCached (NetworkInfo name _ _) =
  let fName = name ++ ".xml"
  in fetchMACs fName

scanAll :: Traversable c => c NetworkInfo -> IO (c [Entry])
scanAll = mapConcurrently scan

scanAllCached :: Traversable c => c NetworkInfo -> IO (c [Entry])
scanAllCached = mapConcurrently scanCached
