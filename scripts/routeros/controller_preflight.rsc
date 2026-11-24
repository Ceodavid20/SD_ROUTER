# Local capability self-test. No network request or configuration write.
# Run on the target device through the trusted initial setup channel.
{
    :do {
        :local sdrProbe [:serialize value={"probe"=1;"literal"="001"} to=json options=json.no-string-conversion];
        :local sdrDecoded [:deserialize from=json value=$sdrProbe options=json.no-string-conversion];
        :if ((($sdrDecoded->"probe") != 1) || (($sdrDecoded->"literal") != "001")) do={ :error "JSON self-test failed"; };
        :local sdrDigest [:convert value="abc" from=raw transform=sha512 to=hex];
        :if ($sdrDigest != "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") do={ :error "SHA512 self-test failed"; };
        :if ([:typeof [:rndnum from=0 to=1]] != "num") do={ :error "Random source unavailable"; };
        :if ([:typeof [:tonum ([:tonsec [:timestamp]] / 1000000000)]] != "num") do={ :error "Timestamp source unavailable"; };
    } on-error={
        :error "SDR prerequisites failed: validate JSON, SHA512, random and timestamp support before installation";
    };
}
