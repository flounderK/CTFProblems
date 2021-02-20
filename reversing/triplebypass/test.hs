module Hasky where

import Data.Bits
import Data.ByteString.Char8 ()
import qualified Data.ByteString as B
--import Data.ByteString.Conversion
import Data.ByteString.Builder
import Data.ByteString.Base64
import Data.Char (ord)
import Foreign.C
import System.IO
s = ["Is this the real life?", "Is this just fantasy?"]

get_encoded_line :: String -> Int -> Integer
get_encoded_line line line_no = result
    where
    result = toInteger (foldl ((+).(*10)) 0 values)
    values = [((x `xor` vowel_count) `xor`(line_no + 1)) | x <- consonant_values]
    consonant_values = [ord a | a <- consonants]
    vowel_count = ((length line) - (length consonants))
    consonants = [ x | x <- line, not (elem x vowels) ]
    vowels = "aeiouyAEIOUY"

-- encode_all_lines :: [IO String] -> Integer
encode_all_lines :: [String] -> Integer
encode_all_lines lines = result
    where
    result = sum encoded_lines
    encoded_lines = [uncurry get_encoded_line args | args <- enumerated_lines]
    enumerated_lines = zip lines [0..]
{-
decrypt :: [String] -> B.ByteString -> String
decrypt lyrics encrypted_data = result
    where
    -- result = decryption_f encrypted_data_raw
    result = show decryption_f
    decryption_f = B.pack . B.zipWith xor
    builder = byteString
    encrypted_data_raw = Data.ByteString.Base64.decode encrypted_data
    key = encode_all_lines lyrics
-}
