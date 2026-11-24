# One authenticated, read-only controller exchange for capable RouterOS 7 devices.
# Render the settings using the controller's private provisioning tool.
# This file never changes interfaces, routes, OSPF costs, or scheduler settings.
{
    :local sdrBaseUrl "__CONTROLLER_BASE_URL__";
    :local sdrRouterId "__ROUTER_ID__";
    :local sdrKeyId "__KEY_ID__";
    :local sdrSharedSecret "__SHARED_SECRET__";

    # SDR_HMAC_BEGIN
    :local sdrHmacSha512 do={
        :local sdrKey $sdrSecret;
        :if ([:len $sdrKey] > 128) do={
            :set sdrKey [:convert value=$sdrKey from=raw transform=sha512 to=raw];
        };
        :local sdrKeyBytes [:convert value=$sdrKey from=raw to=byte-array];
        :local sdrInnerBytes [:toarray ""];
        :local sdrOuterBytes [:toarray ""];
        :for sdrI from=0 to=127 do={
            :local sdrByte 0;
            :if ($sdrI < [:len $sdrKeyBytes]) do={
                :set sdrByte ($sdrKeyBytes->$sdrI);
            };
            :local sdrInnerByte 0;
            :local sdrOuterByte 0;
            :local sdrWeight 1;
            # Arithmetic XOR avoids relying on numeric bitwise operators.
            :for sdrBit from=0 to=7 do={
                :if (((($sdrByte / $sdrWeight) % 2)) != (((54 / $sdrWeight) % 2))) do={
                    :set sdrInnerByte ($sdrInnerByte + $sdrWeight);
                };
                :if (((($sdrByte / $sdrWeight) % 2)) != (((92 / $sdrWeight) % 2))) do={
                    :set sdrOuterByte ($sdrOuterByte + $sdrWeight);
                };
                :set sdrWeight ($sdrWeight * 2);
            };
            :set sdrInnerBytes ($sdrInnerBytes, $sdrInnerByte);
            :set sdrOuterBytes ($sdrOuterBytes, $sdrOuterByte);
        };
        :local sdrInnerPad [:convert value=$sdrInnerBytes from=byte-array to=raw];
        :local sdrOuterPad [:convert value=$sdrOuterBytes from=byte-array to=raw];
        :local sdrInnerHash [:convert value=($sdrInnerPad . $sdrMessage) from=raw transform=sha512 to=raw];
        :return [:convert value=($sdrOuterPad . $sdrInnerHash) from=raw transform=sha512 to=hex];
    };
    # SDR_HMAC_END

    :local sdrUuid do={
        :local sdrHex "0123456789abcdef";
        :local sdrVariant [:pick "89ab" [:rndnum from=0 to=3]];
        :return ([:rndstr from=$sdrHex length=8] . "-" . [:rndstr from=$sdrHex length=4] . "-4" . [:rndstr from=$sdrHex length=3] . "-" . $sdrVariant . [:rndstr from=$sdrHex length=3] . "-" . [:rndstr from=$sdrHex length=12]);
    };

    :local sdrValidateResponse do={
        :if (([:typeof $sdrText] != "str") || ([:len $sdrText] = 0) || ([:len $sdrText] > 8192)) do={
            :error "Invalid controller response size";
        };
        :local sdrValue [:deserialize value=$sdrText from=json options=json.no-string-conversion];
        :if ([:typeof $sdrValue] != "array") do={ :error "Invalid controller response object"; };
        :local sdrExpectedCount 14;
        :local sdrExpectedStatus "authenticated";
        :local sdrExpectedReason "optimization_unavailable";
        :if ([:len $sdrReceiptTarget] > 0) do={
            :set sdrExpectedCount 15;
            :set sdrExpectedStatus "receipt_recorded";
            :set sdrExpectedReason "receipt_recorded";
        };
        :if ([:len $sdrValue] != $sdrExpectedCount) do={ :error "Unexpected controller response fields"; };
        :foreach sdrFieldName in={"protocol_version";"router_id";"request_id";"response_id";"status";"mode";"action";"reason";"issued_at";"expires_at"} do={
            :if ([:typeof ($sdrValue->$sdrFieldName)] != "str") do={ :error "Invalid controller response field type"; };
        };
        :if (($sdrValue->"protocol_version") != "2.0") do={ :error "Unsupported controller protocol"; };
        :if (($sdrValue->"router_id") != $sdrExpectedRouter) do={ :error "Controller response belongs to another router"; };
        :if (($sdrValue->"request_id") != $sdrExpectedRequest) do={ :error "Controller response belongs to another request"; };
        :if (!(($sdrValue->"response_id") ~ "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\$")) do={
            :error "Invalid controller response identity";
        };
        :if ((($sdrValue->"status") != $sdrExpectedStatus) || (($sdrValue->"reason") != $sdrExpectedReason)) do={
            :error "Unexpected controller response status";
        };
        :if ((($sdrValue->"mode") != "dry_run") || (($sdrValue->"action") != "none")) do={
            :error "This client accepts no routing actions";
        };
        :if (([:typeof ($sdrValue->"configuration")] != "array") || ([:len ($sdrValue->"configuration")] != 0)) do={
            :error "This client accepts an empty configuration only";
        };
        # Distinguish an empty JSON object from an empty list after decoding.
        :if (!($sdrText ~ "\"configuration\"[[:space:]]*:[[:space:]]*\\{[[:space:]]*\\}")) do={
            :error "Controller configuration must be a JSON object";
        };
        :foreach sdrTimeName in={"issued_at";"expires_at"} do={
            :if (!(($sdrValue->$sdrTimeName) ~ "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z\$")) do={
                :error "Invalid controller UTC timestamp";
            };
        };
        :foreach sdrNumberName in={"issued_at_unix";"expires_at_unix";"poll_after_seconds"} do={
            :if ([:typeof ($sdrValue->$sdrNumberName)] != "num") do={ :error "Invalid controller numeric field"; };
        };
        :local sdrIssued ($sdrValue->"issued_at_unix");
        :local sdrExpires ($sdrValue->"expires_at_unix");
        :local sdrNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :if (($sdrExpires <= $sdrNow) || ($sdrIssued > ($sdrNow + 30)) || ($sdrExpires <= $sdrIssued) || (($sdrExpires - $sdrIssued) > 300)) do={
            :error "Controller response is expired or has invalid validity";
        };
        :if ((($sdrValue->"poll_after_seconds") < 1) || (($sdrValue->"poll_after_seconds") > 86400)) do={
            :error "Invalid controller polling interval";
        };
        :if ([:len $sdrReceiptTarget] > 0) do={
            :if (([:typeof ($sdrValue->"acknowledged_response_id")] != "str") || (($sdrValue->"acknowledged_response_id") != $sdrReceiptTarget)) do={
                :error "Controller receipt belongs to another response";
            };
        };
        :return $sdrValue;
    };

    :global sdrLastReceivedResponseId;
    :global sdrLastReceivedUnix;
    :global sdrLastReceiptUnix;
    :global sdrLastExchangeState;
    :local sdrStep "settings";

    :do {
        :if (!($sdrBaseUrl ~ "^https://")) do={ :error "A configured HTTPS controller origin is required"; };
        :if (!($sdrRouterId ~ "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\$")) do={ :error "Invalid configured router identity"; };
        :if (!($sdrKeyId ~ "^[A-Z][A-Z0-9_]{0,31}\$")) do={ :error "Invalid configured key identity"; };
        :if (!($sdrSharedSecret ~ "^[0-9a-f]{64}\$")) do={ :error "An individually provisioned router key is required"; };
        :local sdrNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :if ($sdrNow < 1577836800) do={ :error "Synchronize router time before polling"; };
        :local sdrRequestId [$sdrUuid];
        :local sdrPollPath "/api/controller/v2/poll";
        :local sdrBody [:serialize value={"protocol_version"="2.0";"router_id"=$sdrRouterId;"request_id"=$sdrRequestId;"timestamp"=$sdrNow;"request_type"="poll"} to=json options=json.no-string-conversion];
        :local sdrBodyDigest [:convert value=$sdrBody from=raw transform=sha512 to=hex];
        :local sdrCanonical ("SDR-POLL-V2\nPOST\n" . $sdrPollPath . "\n" . $sdrKeyId . "\n" . $sdrBodyDigest);
        :local sdrSignature [$sdrHmacSha512 sdrSecret=$sdrSharedSecret sdrMessage=$sdrCanonical];
        :local sdrHeaders ("Content-Type:application/json,X-SDR-Key-Id:" . $sdrKeyId . ",X-SDR-Signature:" . $sdrSignature);
        :set sdrStep "poll transport";
        :local sdrFetched [/tool/fetch url=($sdrBaseUrl . $sdrPollPath) http-method=post http-data=$sdrBody http-header-field=$sdrHeaders check-certificate=yes http-max-redirect-count=0 output=user as-value duration=__FETCH_TIMEOUT_SECONDS__s];
        :if (($sdrFetched->"status") != "finished") do={ :error "Controller poll did not finish"; };
        :set sdrStep "poll validation";
        :local sdrPollReply [$sdrValidateResponse sdrText=($sdrFetched->"data") sdrExpectedRouter=$sdrRouterId sdrExpectedRequest=$sdrRequestId sdrReceiptTarget=""];
        :local sdrResponseId ($sdrPollReply->"response_id");
        :if ($sdrLastReceivedResponseId = $sdrResponseId) do={ :error "Controller response was already handled"; };
        :set sdrLastReceivedResponseId $sdrResponseId;
        :set sdrLastReceivedUnix [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :set sdrLastExchangeState "response_validated";

        :local sdrAckPath "/api/controller/v2/ack";
        :local sdrAckId [$sdrUuid];
        :local sdrAckNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :local sdrAckBody [:serialize value={"protocol_version"="2.0";"router_id"=$sdrRouterId;"request_id"=$sdrAckId;"timestamp"=$sdrAckNow;"request_type"="ack";"response_id"=$sdrResponseId} to=json options=json.no-string-conversion];
        :local sdrAckDigest [:convert value=$sdrAckBody from=raw transform=sha512 to=hex];
        :local sdrAckCanonical ("SDR-POLL-V2\nPOST\n" . $sdrAckPath . "\n" . $sdrKeyId . "\n" . $sdrAckDigest);
        :local sdrAckSignature [$sdrHmacSha512 sdrSecret=$sdrSharedSecret sdrMessage=$sdrAckCanonical];
        :local sdrAckHeaders ("Content-Type:application/json,X-SDR-Key-Id:" . $sdrKeyId . ",X-SDR-Signature:" . $sdrAckSignature);
        :set sdrStep "receipt transport";
        :local sdrAckFetched [/tool/fetch url=($sdrBaseUrl . $sdrAckPath) http-method=post http-data=$sdrAckBody http-header-field=$sdrAckHeaders check-certificate=yes http-max-redirect-count=0 output=user as-value duration=__FETCH_TIMEOUT_SECONDS__s];
        :if (($sdrAckFetched->"status") != "finished") do={ :error "Controller receipt did not finish"; };
        :set sdrStep "receipt validation";
        :local sdrAckReply [$sdrValidateResponse sdrText=($sdrAckFetched->"data") sdrExpectedRouter=$sdrRouterId sdrExpectedRequest=$sdrAckId sdrReceiptTarget=$sdrResponseId];
        :if (($sdrAckReply->"response_id") = $sdrResponseId) do={ :error "Controller receipt reused response identity"; };
        :set sdrLastReceiptUnix [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :set sdrLastExchangeState "receipt_recorded";
        :log info ("SDR controller response received and acknowledged for " . $sdrRouterId . "; no routing action");
        :put "SDR exchange complete: response validated; receipt recorded; no routing action";
    } on-error={
        :set sdrLastExchangeState ("failed: " . $sdrStep);
        :log warning ("SDR controller exchange failed at " . $sdrStep . "; no routing action");
        :error ("SDR exchange failed at " . $sdrStep);
    };
}
