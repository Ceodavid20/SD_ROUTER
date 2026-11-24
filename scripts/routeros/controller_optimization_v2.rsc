# Disabled advisory pull client. No route, OSPF, firewall or interface writes.
# Install/schedule only after reviewing the private generated client and trust.
{
    :local sdrOptimizationEnabled false;
    :if ($sdrOptimizationEnabled != true) do={ :put "SDR optimization pull disabled"; :return; };
    :local sdrBaseUrl "__CONTROLLER_BASE_URL__";
    :local sdrRouterId "__ROUTER_ID__";
    :local sdrKeyId "__KEY_ID__";
    :local sdrSharedSecret "__SHARED_SECRET__";
__HMAC_HELPER__
    :global sdrAdvisoryVersion;
    :global sdrAdvisoryDecision;
    :do {
        :if (!($sdrBaseUrl ~ "^https://")) do={ :error "Verified HTTPS required"; };
        :local sdrNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :if ($sdrNow < 1577836800) do={ :error "Router clock unavailable"; };
        :local sdrHex "0123456789abcdef";
        :local sdrVariant [:pick "89ab" [:rndnum from=0 to=3]];
        :local sdrNonce ([:rndstr from=$sdrHex length=8] . "-" . [:rndstr from=$sdrHex length=4] . "-4" . [:rndstr from=$sdrHex length=3] . "-" . $sdrVariant . [:rndstr from=$sdrHex length=3] . "-" . [:rndstr from=$sdrHex length=12]);
        :local sdrPath "/api/controller/v2/optimization";
        :local sdrBody [:serialize value={"protocol_version"="2.0";"router_id"=$sdrRouterId;"request_id"=$sdrNonce;"timestamp"=$sdrNow;"request_type"="optimization"} to=json options=json.no-string-conversion];
        :local sdrDigest [:convert value=$sdrBody from=raw transform=sha512 to=hex];
        :local sdrCanonical ("SDR-POLL-V2\nPOST\n" . $sdrPath . "\n" . $sdrKeyId . "\n" . $sdrDigest);
        :local sdrSignature [$sdrHmacSha512 sdrSecret=$sdrSharedSecret sdrMessage=$sdrCanonical];
        :local sdrHeaders ("Content-Type:application/json,X-SDR-Key-Id:" . $sdrKeyId . ",X-SDR-Signature:" . $sdrSignature);
        :local sdrFetched [/tool/fetch url=($sdrBaseUrl . $sdrPath) http-method=post http-data=$sdrBody http-header-field=$sdrHeaders check-certificate=yes http-max-redirect-count=0 output=user as-value duration=10s];
        :if (($sdrFetched->"status") != "finished") do={ :error "Fetch failed"; };
        :local sdrText ($sdrFetched->"data");
        :if (([:typeof $sdrText] != "str") || ([:len $sdrText] = 0) || ([:len $sdrText] > 8192)) do={ :error "Invalid reply size"; };
        :local sdrReply [:deserialize value=$sdrText from=json options=json.no-string-conversion];
        :if (([:typeof $sdrReply] != "array") || ([:len $sdrReply] != 12)) do={ :error "Invalid reply fields"; };
        :if ((($sdrReply->"protocol_version") != "2.0") || (($sdrReply->"router_id") != $sdrRouterId) || (($sdrReply->"request_id") != $sdrNonce)) do={ :error "Reply identity mismatch"; };
        :if ((($sdrReply->"mode") != "advisory") || (($sdrReply->"action") != "none") || (($sdrReply->"execution_authorized") != false) || (($sdrReply->"routing_changes_enabled") != false)) do={ :error "Execution is not authorized for this client"; };
        :local sdrIssued ($sdrReply->"issued_at_unix");
        :local sdrExpires ($sdrReply->"expires_at_unix");
        :local sdrCheckNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :if (([:typeof $sdrIssued] != "num") || ([:typeof $sdrExpires] != "num")) do={ :error "Invalid validity fields"; };
        :if (($sdrExpires <= $sdrCheckNow) || ($sdrIssued > ($sdrCheckNow + 30)) || ($sdrExpires <= $sdrIssued) || (($sdrExpires - $sdrIssued) > 300)) do={ :error "Expired reply"; };
        :if (($sdrReply->"status") = "optimization_unavailable") do={ :put "SDR optimization unavailable; no routing action"; :return; };
        :if (($sdrReply->"status") != "advisory_recommendation") do={ :error "Unexpected reply state"; };
        :local sdrDecision ($sdrReply->"recommendation");
        :if (([:typeof $sdrDecision] != "array") || (($sdrDecision->"aggregation_router_id") != $sdrRouterId) || (($sdrDecision->"execution_authorized") != false)) do={ :error "Invalid scoped recommendation"; };
        :local sdrVersion ($sdrDecision->"decision_version");
        :local sdrDecisionId ($sdrDecision->"decision_id");
        :if (([:typeof $sdrVersion] != "num") || ($sdrVersion < 1) || ($sdrVersion != [:tonum [:tostr $sdrVersion]]) || ([:typeof $sdrDecisionId] != "str") || (!($sdrDecisionId ~ "^[0-9a-f]{64}\$"))) do={ :error "Invalid decision version"; };
        :if ([:typeof $sdrAdvisoryVersion] = "num") do={
            :if ($sdrVersion < $sdrAdvisoryVersion) do={ :error "Old decision rejected"; };
            :if (($sdrVersion = $sdrAdvisoryVersion) && ($sdrDecisionId != $sdrAdvisoryDecision)) do={ :error "Conflicting decision version"; };
        };
        # Advisory metadata only; never parse or execute controller-supplied code.
        :set sdrAdvisoryVersion $sdrVersion;
        :set sdrAdvisoryDecision $sdrDecisionId;
        :local sdrResultNonce ([:rndstr from=$sdrHex length=8] . "-" . [:rndstr from=$sdrHex length=4] . "-4" . [:rndstr from=$sdrHex length=3] . "-" . $sdrVariant . [:rndstr from=$sdrHex length=3] . "-" . [:rndstr from=$sdrHex length=12]);
        :local sdrResultPath "/api/controller/v2/optimization/result";
        :local sdrResultNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :local sdrResultBody [:serialize value={"protocol_version"="2.0";"router_id"=$sdrRouterId;"request_id"=$sdrResultNonce;"timestamp"=$sdrResultNow;"request_type"="optimization_result";"response_id"=($sdrReply->"response_id");"decision_id"=$sdrDecisionId;"decision_version"=$sdrVersion;"result"="not_applied"} to=json options=json.no-string-conversion];
        :local sdrResultDigest [:convert value=$sdrResultBody from=raw transform=sha512 to=hex];
        :local sdrResultCanonical ("SDR-POLL-V2\nPOST\n" . $sdrResultPath . "\n" . $sdrKeyId . "\n" . $sdrResultDigest);
        :local sdrResultSignature [$sdrHmacSha512 sdrSecret=$sdrSharedSecret sdrMessage=$sdrResultCanonical];
        :local sdrResultHeaders ("Content-Type:application/json,X-SDR-Key-Id:" . $sdrKeyId . ",X-SDR-Signature:" . $sdrResultSignature);
        :local sdrReported [/tool/fetch url=($sdrBaseUrl . $sdrResultPath) http-method=post http-data=$sdrResultBody http-header-field=$sdrResultHeaders check-certificate=yes http-max-redirect-count=0 output=user as-value duration=10s];
        :if (($sdrReported->"status") != "finished") do={ :error "Result report failed"; };
        :put "SDR advisory retrieved; reported not applied; no routing action";
    } on-error={
        :log warning "SDR advisory retrieval failed; no routing action";
        :error "SDR advisory retrieval failed";
    };
}
