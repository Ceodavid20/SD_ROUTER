# PRIVATE one-time bootstrap. Deliver this file and its public CA by a trusted method.
# It needs initial connectivity, a valid clock and installation privileges.
# The installed collector and scheduler have only read,test permissions.
{
    :local sdrOrigin "__CONTROLLER_ORIGIN__";
    :local sdrToken "__ENROLLMENT_TOKEN__";
    :local sdrInterface "__OUTBOUND_INTERFACE__";
    :local sdrCAFile "__CA_FILENAME__";
    :do {
        :if (!($sdrOrigin ~ "^https://")) do={ :error "Verified HTTPS is required"; };
        :local sdrInterfaceId [/interface/find where name=$sdrInterface];
        :if ([:len $sdrInterfaceId] != 1) do={ :error "Configure one outbound interface"; };
        /certificate/import file-name=$sdrCAFile trusted=yes;
        :local sdrHex "0123456789abcdef";
        :local sdrVariant [:pick "89ab" [:rndnum from=0 to=3]];
        :local sdrRequestId ([:rndstr from=$sdrHex length=8] . "-" . [:rndstr from=$sdrHex length=4] . "-4" . [:rndstr from=$sdrHex length=3] . "-" . $sdrVariant . [:rndstr from=$sdrHex length=3] . "-" . [:rndstr from=$sdrHex length=12]);
        :local sdrNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
        :local sdrDeviceId ("bootstrap-" . $sdrRequestId);
        :local sdrEthernet [/interface/ethernet/find];
        :if ([:len $sdrEthernet] > 0) do={
            :set sdrDeviceId [/interface/ethernet/get [:pick $sdrEthernet 0] mac-address];
        };
        :local sdrBody [:serialize value={"protocol_version"="1.0";"request_type"="enroll";"request_id"=$sdrRequestId;"timestamp"=$sdrNow;"router_name"=[/system/identity/get name];"device_id"=$sdrDeviceId;"interface"=$sdrInterface} to=json options=json.no-string-conversion];
        :local sdrHeaders ("Content-Type:application/json,Authorization:Bearer " . $sdrToken);
        :local sdrFetched;
        :local sdrFinished false;
        :for sdrAttempt from=1 to=3 do={
            :if ($sdrFinished != true) do={
                :set sdrNow [:tonum ([:tonsec [:timestamp]] / 1000000000)];
                :set sdrBody [:serialize value={"protocol_version"="1.0";"request_type"="enroll";"request_id"=$sdrRequestId;"timestamp"=$sdrNow;"router_name"=[/system/identity/get name];"device_id"=$sdrDeviceId;"interface"=$sdrInterface} to=json options=json.no-string-conversion];
                :do {
                    :set sdrFetched [/tool/fetch url=($sdrOrigin . "/api/controller/v2/enroll") http-method=post http-data=$sdrBody http-header-field=$sdrHeaders check-certificate=yes http-max-redirect-count=0 output=user as-value duration=15s];
                    :set sdrFinished (($sdrFetched->"status") = "finished");
                } on-error={ :if ($sdrAttempt < 3) do={ :delay 5s; }; };
            };
        };
        :if ($sdrFinished != true) do={ :error "Enrollment transport is unavailable"; };
        :if (($sdrFetched->"status") != "finished") do={ :error "Enrollment did not finish"; };
        :local sdrText ($sdrFetched->"data");
        :if (([:typeof $sdrText] != "str") || ([:len $sdrText] = 0) || ([:len $sdrText] > 65536)) do={ :error "Invalid enrollment response"; };
        :local sdrReply [:deserialize value=$sdrText from=json options=json.no-string-conversion];
        :if (([:typeof $sdrReply] != "array") || ([:len $sdrReply] != 11)) do={ :error "Invalid enrollment response fields"; };
        :if ((($sdrReply->"protocol_version") != "1.0") || (($sdrReply->"status") != "enrolled") || (($sdrReply->"request_id") != $sdrRequestId)) do={ :error "Enrollment identity mismatch"; };
        :if ((($sdrReply->"interface") != $sdrInterface) || (($sdrReply->"mode") != "dry_run") || (($sdrReply->"action") != "monitoring_setup") || (($sdrReply->"routing_changes_enabled") != false)) do={ :error "Unexpected enrollment policy"; };
        :local sdrSource ($sdrReply->"collector_source");
        :local sdrInterval ($sdrReply->"interval_seconds");
        :local sdrEnabled ($sdrReply->"monitoring_enabled");
        :if (([:typeof $sdrSource] != "str") || ([:len $sdrSource] = 0) || ([:len $sdrSource] > 60000)) do={ :error "Invalid collector"; };
        :if (([:typeof $sdrInterval] != "num") || ($sdrInterval < 1) || ($sdrInterval > 86400) || ([:typeof $sdrEnabled] != "bool")) do={ :error "Invalid monitoring interval"; };
        :local sdrScript [/system/script/find where name="sdr-controller-traffic"];
        :local sdrScheduler [/system/scheduler/find where name="sdr-controller-traffic"];
        :if (([:len $sdrScript] > 1) || ([:len $sdrScheduler] > 1)) do={ :error "Monitoring names are not unique"; };
        :if ([:len $sdrScheduler] = 1) do={ /system/scheduler/set $sdrScheduler disabled=yes; };
        :if ([:len $sdrScript] = 0) do={
            /system/script/add name="sdr-controller-traffic" policy=read,test dont-require-permissions=no source=$sdrSource;
        } else={
            /system/script/set $sdrScript policy=read,test dont-require-permissions=no source=$sdrSource;
        };
        :local sdrPeriod ([:tostr $sdrInterval] . "s");
        :local sdrEvent "/system/script/run sdr-controller-traffic use-script-permissions";
        :if ([:len $sdrScheduler] = 0) do={
            /system/scheduler/add name="sdr-controller-traffic" interval=$sdrPeriod start-time=00:00:00 disabled=yes policy=read,test on-event=$sdrEvent;
            :set sdrScheduler [/system/scheduler/find where name="sdr-controller-traffic"];
        } else={
            /system/scheduler/set $sdrScheduler interval=$sdrPeriod start-time=00:00:00 policy=read,test on-event=$sdrEvent;
        };
        /system/scheduler/set $sdrScheduler disabled=(!$sdrEnabled);
        :if ($sdrEnabled = true) do={
            :do { /system/script/run sdr-controller-traffic use-script-permissions; } on-error={
                :log warning "SDR first TX request failed; the monitoring scheduler will retry";
            };
        };
        :put "SDR bootstrap completed; monitoring configuration installed";
    } on-error={
        # Never print Fetch errors, private headers, tokens or response text.
        :log warning "SDR enrollment failed; check connectivity and bootstrap authorization";
        :error "SDR enrollment failed";
    };
}
