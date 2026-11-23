# Separate optional TX collector. Disabled until an administrator enables it.
# No poll/ACK changes, interface writes, counter resets or scheduler installation.
{
    :local sdrTrafficEnabled false;
    :if ($sdrTrafficEnabled != true) do={
        :put "SDR outbound collection is disabled";
        :return;
    };
    :local sdrBaseUrl "__CONTROLLER_BASE_URL__";
    :local sdrRouterId "__ROUTER_ID__";
    :local sdrKeyId "__KEY_ID__";
    :local sdrSharedSecret "__SHARED_SECRET__";
    :local sdrInterface "__INTERFACE__";

__HMAC_HELPER__

    :do {
        :if (!($sdrBaseUrl ~ "^https://")) do={ :error "Verified HTTPS is required"; };
        :if ([:len $sdrInterface] = 0) do={ :error "An outbound interface is required"; };
        :local sdrInterfaceId [/interface/find where name=$sdrInterface];
        :if ([:len $sdrInterfaceId] != 1) do={ :error "Expected exactly one configured interface"; };
        # Read only the selected interface's cumulative outbound octets.
        :local sdrTxOctets [:tonum [/interface/get $sdrInterfaceId value-name=tx-byte]];
        :if (([:typeof $sdrTxOctets] != "num") || ($sdrTxOctets < 0)) do={ :error "Invalid TX counter"; };
        :local sdrNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :if ($sdrNow < 1577836800) do={ :error "Synchronize router time before sampling"; };
        :local sdrHex "0123456789abcdef";
        :local sdrVariant [:pick "89ab" [:rndnum from=0 to=3]];
        :local sdrRequestId ([:rndstr from=$sdrHex length=8] . "-" . [:rndstr from=$sdrHex length=4] . "-4" . [:rndstr from=$sdrHex length=3] . "-" . $sdrVariant . [:rndstr from=$sdrHex length=3] . "-" . [:rndstr from=$sdrHex length=12]);
        :local sdrPath "/api/controller/v2/traffic";
        :local sdrBody [:serialize value={"protocol_version"="2.0";"router_id"=$sdrRouterId;"request_id"=$sdrRequestId;"timestamp"=$sdrNow;"request_type"="traffic";"interface"=$sdrInterface;"tx_octets"=$sdrTxOctets} to=json options=json.no-string-conversion];
        :local sdrBodyDigest [:convert value=$sdrBody from=raw transform=sha512 to=hex];
        :local sdrCanonical ("SDR-POLL-V2\nPOST\n" . $sdrPath . "\n" . $sdrKeyId . "\n" . $sdrBodyDigest);
        :local sdrSignature [$sdrHmacSha512 sdrSecret=$sdrSharedSecret sdrMessage=$sdrCanonical];
        :local sdrHeaders ("Content-Type:application/json,X-SDR-Key-Id:" . $sdrKeyId . ",X-SDR-Signature:" . $sdrSignature);
        :local sdrFetched [/tool/fetch url=($sdrBaseUrl . $sdrPath) http-method=post http-data=$sdrBody http-header-field=$sdrHeaders check-certificate=yes http-max-redirect-count=0 output=user as-value duration=10s];
        :if (($sdrFetched->"status") != "finished") do={ :error "Traffic request did not finish"; };
        :local sdrText ($sdrFetched->"data");
        :if (([:typeof $sdrText] != "str") || ([:len $sdrText] = 0) || ([:len $sdrText] > 8192)) do={ :error "Invalid traffic response"; };
        :local sdrReply [:deserialize value=$sdrText from=json options=json.no-string-conversion];
        :if ([:typeof $sdrReply] != "array") do={ :error "Invalid traffic response object"; };
        :if ((($sdrReply->"protocol_version") != "2.0") || (($sdrReply->"router_id") != $sdrRouterId) || (($sdrReply->"request_id") != $sdrRequestId)) do={ :error "Traffic response identity mismatch"; };
        :if ((($sdrReply->"status") != "traffic_recorded") || (($sdrReply->"mode") != "dry_run") || (($sdrReply->"action") != "none")) do={ :error "Unexpected traffic response state"; };
        :if (([:typeof ($sdrReply->"configuration")] != "array") || ([:len ($sdrReply->"configuration")] != 0)) do={ :error "Unexpected traffic configuration"; };
        :if (!($sdrText ~ "\"configuration\"[[:space:]]*:[[:space:]]*\\{[[:space:]]*\\}")) do={ :error "Expected empty configuration object"; };
        :put "SDR outbound counter accepted; no routing action";
    } on-error={
        # Never echo Fetch errors, headers, private settings or response text.
        :log warning "SDR outbound collection failed; verify controller monitoring";
        :error "SDR outbound collection failed";
    };
}
