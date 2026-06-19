Queries and mentionned applied strategies in no particular order. 

## Good AitM candidates

This query identifies users who signed in to the OfficeHome application (the most commonly targeted app in AiTM phishing attacks) today from an unmanaged device, where that user has never successfully done so in the previous 90 days. A first-time unmanaged OfficeHome sign-in is a interresting indicator of a potential AiTM compromise.


**Kool-ql stuff**
- [arg_max()](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function)
- [leftanti](https://learn.microsoft.com/en-us/kusto/query/join-leftanti) join 

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where AppDisplayName == "OfficeHome"
| where isempty(DeviceDetail.deviceId)
| summarize arg_max(TimeGenerated, UserPrincipalName, IPAddress, Location) by Id
| join kind=leftanti (
    SigninLogs
    | where TimeGenerated between (ago(90d) .. ago(1d))
    | where AppDisplayName == "OfficeHome"
    | where isempty(DeviceDetail.deviceId)
    | summarize arg_max(TimeGenerated, UserPrincipalName, ResultType) by Id
    | where ResultType == 0
) on UserPrincipalName
```

## Geo-Fencing block

This query finds sign-in attempts to OfficeHome from unmanaged devices that were blocked by a geo-fencing Conditional Access Policy. While the block prevented access, the user's password is still compromised (Conditional Access evaluation only occurs after first-factor authentication succeeds). A geo-fencing block confirms the credentials are valid but used from an unauthorized location.


**Kool-ql stuff**
- [arg_max()](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function)
- [mv-apply](https://learn.microsoft.com/en-us/kusto/query/mv-apply-operator)


```kql
let GeoFencingCAP = pack_array("CAP1 - No access outside of Canada","CAP3 - No access from Europe") ;
SigninLogs
| where ResultType == 53003
| where isempty(DeviceDetail.deviceId)
| where AppDisplayName == "OfficeHome"
| summarize arg_max(CreatedDateTime, UserPrincipalName, ConditionalAccessPolicies, SessionId) by Id
| mv-apply ConditionalAccessPolicies on (
    where ConditionalAccessPolicies.displayName in (GeoFencingCAP)
      and ConditionalAccessPolicies.result == "failure"
)
```

> The same logic could be applied for CAP failures because of device requirements.

## Self-Remediated Risk from Unmanaged Devices

This query surfaces successful sign-in attempts from unmanaged devices that triggered an Entra ID sign-in risk, where the user self-remediated by completing MFA. In an AiTM scenario, the attacker relays the MFA challenge to the legitimate user ; so a risk that appears "resolved" via MFA from an unmanaged device may actually indicate a compromised session rather than a legitimate login.
You can also filter on OfficeHome app.

**Kool-ql stuff**
- [mv-apply](https://learn.microsoft.com/en-us/kusto/query/mv-apply-operator)

```kql
let NonPhishResistantMFA = dynamic(["Mobile app notification","OATH verification code","Text message","Phone call approval (Authentication phone)","Phone call approval (Alternate phone)","Passwordless phone sign-in","Phone call approval (Office phone)","Passwordless Microsoft Authenticator","Other"]);
SigninLogs
| where TimeGenerated > ago(90d)
| where RiskEventTypes has "unfamiliarFeatures"
| where isempty(DeviceDetail.deviceId)
| where RiskState == "remediated"
| mv-apply AuthenticationDetails = todynamic(AuthenticationDetails) to typeof(dynamic) on (
    where AuthenticationDetails.authenticationMethod has_any (NonPhishResistantMFA)
    | extend Method = AuthenticationDetails.authenticationMethod
) | project TimeGenerated, UserPrincipalName, Method, AppDisplayName
```

## Token blast radius

Given a compromised session ID, this query enumerates all token requests made within that session and filters for tokens not using Continuous Access Evaluation (CAE). Non-CAE bearer tokens remain valid even after the user's access has been revoked, representing the true blast radius of the compromise.

**Kool-ql stuff**
- [mv-apply](https://learn.microsoft.com/en-us/kusto/query/mv-apply-operator)
- [arg_max()](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function)

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where SessionId == "004d167a-7f07-a497-25b4-34215bdfd62f"
| mv-apply CAECheck = todynamic(AuthenticationProcessingDetails) on (
    extend CAE = iif(CAECheck.key == "Is CAE Token" and CAECheck.value == "False", False, True)
)
| summarize arg_max(CreatedDateTime,CreatedDateTime, UserPrincipalName, SessionId, ResultType, AppDisplayName, ResourceDisplayName, CAE) by UniqueTokenIdentifier
| where CAE == false
```


## Unusual login locations

Establish a baseline by reviewing the last 90 days of successful sign-in activity up to yesterday, excluding any sessions known to be compromised. Then examine all successful sessions from today, mapping each user's connection origin and surrounding geographic area. Finally, surface any connections originating from a geographic area the user has never signed in from before.

**Kool-ql stuff**
- [geo_point_to_s2cell()](https://learn.microsoft.com/en-us/kusto/query/geo-point-to-s2cell-function)
- [geo_s2cell_neighbors()](https://learn.microsoft.com/en-us/kusto/query/geo-s2cell-neighbors-function)
- [leftanti](https://learn.microsoft.com/en-us/kusto/query/join-leftanti) join 


```kql
let CompromisedSessionId = pack_array("ecb707e9-67ab-4a45-8894-d3a528336d64","ea5bd3fe-736d-4f4f-b803-2ccafd175f8e");
let LookBackStart = ago(90d);
let LookBackEnd = ago(1d);
let ZoomLevel = 6; //6:150km 5:315km
SigninLogs
| where TimeGenerated > LookBackEnd
| where ResultType == 0
| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
| extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| extend GeoHash = geo_point_to_s2cell(Longitude, Latitude, ZoomLevel)
| extend LocationText = strcat(LocationDetails.city, ", ",LocationDetails.state, ", ", LocationDetails.countryOrRegion)
| summarize Places = make_set(LocationText) by UserPrincipalName, GeoHash
| join kind=leftanti (
    SigninLogs
    | where TimeGenerated between (LookBackStart .. LookBackEnd)
    | where SessionId !in (CompromisedSessionId)
    | where ResultType == 0
    | extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
    | extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
    | extend GeoHash = geo_point_to_s2cell(Longitude, Latitude,ZoomLevel)
    | extend GeoArea = array_concat(geo_s2cell_neighbors(GeoHash), pack_array(GeoHash))
    | mv-expand GeoArea to typeof(string) 
) on UserPrincipalName, $left.GeoHash == $right.GeoArea
```


## Consecutive almost nefarious actions

This query combines multiple lower-fidelity activity signals and identifies actions performed in a specific sequence within a defined time window.

**Kool-ql stuff**
- [partition](https://learn.microsoft.com/en-us/kusto/query/partition-operator)
- [scan](https://learn.microsoft.com/en-us/kusto/query/scan-operator)

```kql
let lookback = 90d;
union (
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where RiskDetail == "userPassedMFADrivenByRiskBasedPolicy" or RiskState == "remediated" 
    | where isempty(DeviceDetail.deviceId)
    | project ActionType = "SuspiciousSignin", ActionTime = CreatedDateTime, UserPrincipalName = tolower(UserPrincipalName)
),(
    AuditLogs
    | where TimeGenerated > ago(lookback)
    | where Category == "UserManagement"
    | where Result == "success"
    | where OperationName == "User registered security info"
    | project ActionType = "NewMFARegistered", ActionTime = ActivityDateTime,
              UserPrincipalName = tolower(tostring(TargetResources[0].userPrincipalName))
),(
    OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where RecordType == "ExchangeAdmin"
    | where Operation == "New-InboxRule"
    | extend SessionId = tostring(AppAccessContext.AADSessionId)
    | project ActionType = "NewInboxRule", ActionTime = Start_Time, RuleParameters = Parameters, UserPrincipalName = tolower(UserId)
)
| partition hint.strategy=native by UserPrincipalName (
    order by ActionTime asc 
    | scan declare (SuspiciousLogonTime:datetime, SuspiciousMFARegistration:datetime) with (
        step s1 output=none: ActionType == "SuspiciousSignin" ;
        step s2 output=none: ActionType == "NewMFARegistered" and ((ActionTime - s1.ActionTime) / 1m) < 5 ;
        step s3: ActionType == "NewInboxRule" and ((ActionTime - s2.ActionTime) / 1m) < 60 =>
            SuspiciousLogonTime = s1.ActionTime, SuspiciousMFARegistration = s2.ActionTime ;
    )
) | project SuspiciousLogonTime, SuspiciousMFARegistration, NewInboxRuleTime = ActionTime, RuleParameters
```


## Suspiciously Regular Token Refresh Patterns

This query identifies sessions originating from the OfficeHome application (configurable to other apps) and then examines non-interactive token refreshes between Outlook and Exchange Online within those sessions. It flags sessions where consecutive token requests consistently fall within a 55- to 65-second interval ; a cadence too uniform to be driven by normal user activity, suggesting automated tooling such as an AiTM proxy replaying stolen tokens.

**Kool-ql stuff**
- [partition](https://learn.microsoft.com/en-us/kusto/query/partition-operator)
- [prev()](https://learn.microsoft.com/en-us/kusto/query/prev-function)
- [row_cumsum()](https://learn.microsoft.com/en-us/kusto/query/row-cumsum-function)


```kql
let ssid = SigninLogs
| where TimeGenerated > ago(180d)
| where AppDisplayName == "OfficeHome"
| where isempty(DeviceDetail.deviceId)
| where ResultType in (0,50140)
//| where RiskLevelDuringSignIn != "none"
| distinct SessionId //, UserPrincipalName
;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(180d)
| where SessionId in (ssid)
| where ResultType == 0
| where AppDisplayName == "Microsoft Outlook"
| where ResourceDisplayName == "Office 365 Exchange Online"
| project CreatedDateTime, SessionId, UserPrincipalName, AppDisplayName, ResourceDisplayName, UserAgent
| partition hint.strategy=native by SessionId (
    order by CreatedDateTime asc
    | extend Delta = ( next(CreatedDateTime) - CreatedDateTime ) / 1s
    | extend in_range = Delta between (55 .. 65)
    //| extend break = iif(in_range == false  or prev(in_range) == false, 1, 0)   // optional: max jump
    | extend group_id = row_cumsum(in_range)
| summarize 
    start_time = min(CreatedDateTime),
    end_time = max(CreatedDateTime),
    count = count(),
    make_set(UserAgent),
    min_val = min(Delta),
    max_val = max(Delta)
    by group_id, SessionId, UserPrincipalName
)
| where ['count'] > 1
```

## User Agent Switch Within an Outlook Session

This query detects sessions where the user agent changes mid-session for Outlook operating as a public client. A legitimate session typically maintains a consistent user agent throughout its lifetime. A shift in user agent within the same session suggests the token may have been exfiltrated and replayed from a different client or tool.


```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType == 0
| where isempty(todynamic(DeviceDetail).deviceId)
| where AppDisplayName == "Microsoft Outlook"
| where ResourceDisplayName == "Office 365 Exchange Online"
| summarize UserAgents = make_set(UserAgent) by SessionId, AppDisplayName, ResourceDisplayName
| where array_length(UserAgents) > 1
```


## Session Travel Distance

This query calculates the cumulative geographic distance (in kilometers) between consecutive sign-in events within the same session. By summing the distance traveled across all token requests in a session, it highlights sessions exhibiting impossible or improbable travel - a weak indicator that the session token is being used from multiple distinct locations, such as when a stolen token is replayed from a different geographic origin.


**Kool-ql stuff**
- [partition](https://learn.microsoft.com/en-us/kusto/query/partition-operator)
- [prev()](https://learn.microsoft.com/en-us/kusto/query/prev-function)
- [row_cumsum()](https://learn.microsoft.com/en-us/kusto/query/row-cumsum-function)
- [geo_distance_2points()](https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function)
 

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where ResultType == 0
| extend Latitude = toreal(todynamic(LocationDetails).geoCoordinates.latitude)
| extend Longitude = toreal(todynamic(LocationDetails).geoCoordinates.longitude)
| project CreatedDateTime, Longitude, Latitude, SessionId
| partition hint.strategy=native by SessionId (
    order by CreatedDateTime asc 
    | extend Distance = geo_distance_2points(Longitude, Latitude, prev(Longitude), prev(Latitude))
    | extend Track = row_cumsum(Distance) //could be reset if time difference is too large
    | project CreatedDateTime, SessionId, Distance, Track
)
| where Track > 0
| summarize max(Track), min(CreatedDateTime), max(CreatedDateTime) by SessionId
| lookup (
    AADNonInteractiveUserSignInLogs 
    | where TimeGenerated > ago(90d)
    | summarize Locations = make_list(Location) by SessionId
) on SessionId
```