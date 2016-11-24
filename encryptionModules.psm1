################################################## Get-PasswordConfirmation ########################################################

function Get-PasswordConfirmation {

<#
    .SYNOPSIS
        This function will gather a password as a secure string twice, then decrypt the inputs so that a check can be made that they were entered
        in correctly.
    .DESCRIPTION
        The function is used to compare the input of secure strings. If a match wasn't made, then the function is re-run until the password has been
        entered correctly, two consequtive times or if a forced script exit is induced. The output is saved to a global custom variable so that it
        can be used in multiple functions. The output can be saved in clear text or secure string. This can be helpful when creating strings where the
        password needs to be entered as clear text (eg the SQL Connection string).
    .PARAMETER Message
        Type a custom message to appear when the prompt to enter a password appears
    .PARAMETER OutAsSecure
        This is a switch. When present, the output is saved as a secure string rather than a clear text password.
    .PARAMETER OutVarName
        This is the name of the global variable that will be used outside the scope of this function.
    .EXAMPLE
        Get-PasswordConfirmation -Message "Please enter a password here" -OutVarName MyPassword
        This example will save the password entered at the prompt as a variable called $MyPassword in clear text
    .EXAMPLE
        Get-PasswordConfirmation -Message "Please enter a secure password here" -OutVarName MySecurePassword -OutAsSecure
        This example will save the password entered as a secure string
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 22/11/2016 16:38
#>

    param(
        [string]$Message,
        [switch]$OutAsSecure,
        [Parameter(mandatory=$true)][string]$outVarName
    )

      # Gather password from user twice and save variable as a secure string
    $input = read-host $message -AsSecureString
    $input2 = read-host "CONFIRM: $message" -AsSecureString

      # Create 2 new variables which will decrypt the secure passwords into clear text in order to compare them both
    $chkPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input))
    $chkPwd2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input2))

    if ($chkPwd -ne $chkPwd2) {

          # If the passwords entered don't match - run the function again until the user escapes or enters a pair of matching passwords
        Write-Warning "The password you entered did not match, please try again!"
        Get-PasswordConfirmation -message $message -outVarName $outVarName

    } else {

        if ($outAsSecure) {

              # If passwords match, create a new variable named after the entered parameter and save as system.secure.string type
            New-Variable -name $outVarName -Value $input -Scope Global -Force

        } else {
            
              # If passwords match, create a new variable named after the entered parameter and save as clear text string
            New-Variable -name $outVarName -Value $chkPwd -Scope Global -Force

        }

    }

}

######################################################## Test-PathCheck ############################################################

Function Test-PathCheck {

<#
    .SYNOPSIS
        This function will test the path that a user inputs. If it doesn't exist it will throw a warning message and loop the
        function again
    .DESCRIPTION
        This function will test the path that a user inputs. If it doesn't exist it will throw a warning message and loop the
        function again
    .PARAMETER Message
        Type a custom message to appear.
    .PARAMETER OutVarName
        This is the name of the global variable that will be used outside the scope of this function.
    .EXAMPLE
        Test-PathCheck -Message "Enter the path to the file" -OutVarName CertFilePath
        If the file specified was found, then this will save the path entered at the prompt as a variable called CertFilePath
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 24/11/2016 11:54
#>

    param(
        [Parameter(Mandatory=$true)][string]$message,
        [Parameter(Mandatory=$true)][string]$OutVarName
    )

    $filePath = Read-Host $message

    if (!(Test-Path $filePath)) {

        Write-Warning "Could not find the specified file. If you are sure the file exists in the specified location, you may not have permission to it"
        Test-PathCheck -message $message

    } else {

        New-Variable -name $OutVarName -Value $filePath -Scope Global -Force

    }

}

################################################## New-TimeCloudCustomerCert #######################################################

Function New-TimeCloudCustomerCert {

<#
    .SYNOPSIS
        This function will create a new self-signed certificate and export 2 certificate files, one with the private key and one without
        the private key.
    .DESCRIPTION
        The function will create a self-signed certificate named after the input of the $customerName parameter and save it in the 
        localmachine's personal certificate store. If the export parameter has been specified, then the script will output three files,
        one certificate with the private key, another with only the public key and a text file with the certificate password saved in clear
        text.
        The function will also remove the certificate from the personal store of the local machine so that no unauthorised person can use
        it to decrypt data.
    .PARAMETER customerName
        The name of the customer for which this certificate is to be used.
    .PARAMETER OutFolder
        The location for the exported certificate files.
    .PARAMETER Export
        This is a switch, if present then the script will output the certificates to the OutFolder location.
    .EXAMPLE
        New-TimeCloudCustomerCert -customerName FirmTest1 -outFolder c:\certs\ -export -passwordOutFile c:\certs\certificatePassword.txt
        This example will create a certificate called TC_FirmTest1_Cert and output it as 2 separate files (one with the key and one without)
        in the c:\certs\ directory.
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 22/11/2016 16:51
#>

    param(
        [string]$customerName,
        [string]$passwordOutFile,
        [string]$outFolder,
        [switch]$export
    )

    if (!(test-path $outFolder)) {

        mkdir $outFolder

    }

    cd $outFolder
    $certSubject = "TC_$customerName" + "_Cert"

    if (Get-ChildItem -Path cert:\localmachine\my\ | where {$_.subject -like "*$certSubject*"}) {

        write-warning "A certificate called $certSubject was found in the local machine's personal certificate store."

    } else {

        New-SelfSignedCertificate -Type Custom -Subject $certSubject -Provider "Microsoft Strong Cryptographic Provider" -KeySpec KeyExchange -KeyLength 4096

        if ($export) {

            # Get the password used to encrypt the .pfx certificate file and save as a secure string
            Get-PasswordConfirmation -outVarName certPassword -Message "Enter a password for the certificate" -outAsSecure
            Get-ChildItem -Path cert:\localmachine\my\ | where {$_.subject -like "*$certSubject*"} | Export-PfxCertificate -FilePath "$outFolder\$certSubject.pfx" -Password $certPassword
            Get-ChildItem -Path cert:\localmachine\my\ | where {$_.subject -like "*$certSubject*"} | Export-Certificate -FilePath "$outFolder\$certSubject.cer"

            #Save the Password for the certificate to the passwordOutFile
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($certPassword)) | out-file $passwordOutFile

            # Remove the certificate from the store so no unauthorised person can use it
            Get-ChildItem -Path cert:\localmachine\my\ | where {$_.subject -like "*$certSubject*"} | Remove-Item

        }

    }

}

#################################################### New-StringEncrypt #############################################################

Function New-StringEncrypt {

<#
    .SYNOPSIS
        This function will encrypt a clear text string using the public key of a certificate file
    .DESCRIPTION
        This function will encrypt a clear text string passed into the ClearText parameter and output it to a .txt file in the OutPath 
        parameter.
    .PARAMETER ClearText
        The text which is to be encrypted.
    .PARAMETER PublicCertFilePath
        The path to the certificate file which contains the public cert.
    .PARAMETER OutPath
        The output path for the text file where the encrypted data is output to.
    .EXAMPLE
        $SomeText = "This is a sentence"
        New-StringEncrypt -ClearText $someText -PublicCertFilePath c:\certs\TC_FirmTest1_Cert.cer -OutPath c:\certs\encryptedText.txt
        This example will encrypt the contents of the $someText variable and output the result to c:\certs\encryptedText.txt
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 22/11/2016 16:57
#>

    param(
        [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]$ClearText,
        [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][ValidateScript({Test-Path $_ -PathType Leaf})][System.String]$PublicCertFilePath,
        [Parameter(Position=2, Mandatory=$true)][string]$OutPath
    )

    $PublicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PublicCertFilePath)
    $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($ClearText)
    $EncryptedByteArray = $PublicCert.PublicKey.Key.Encrypt($ByteArray,$true)
    $EncryptedBase64String = [Convert]::ToBase64String($EncryptedByteArray)

    $EncryptedBase64String | Out-File $OutPath

}

#################################################### New-ConnectionString ##########################################################

function New-ConnectionString {

<#
    .SYNOPSIS
        This function will build a connection string to connect to an SQL instance.
    .DESCRIPTION
        This function will build a connection string based on typical parameters needed to connect to an SQL instance using SQL credentials
        and not Integrated Pass-Through credentials. As the requirement was to hide the password for the SQL user, the output of this 
        function is encrypted using the public key of a specified certificate.
        The Get-PasswordConfirmation and New-StringEncrypt functions are relied upon for this function to work.
        The format of the connection string is: 
            Data Source=$HAGListener\$SQLInstance;Initial Catalog=$Database;User ID=$SQLUsername;Password=password;Persist Security Info=True;
        The password for the connection string is prompted for as a secure string (therefore it won't be seen on the screen when typed in) and is
        saved as the $SQLPassword variable.
    .PARAMETER SQLUsername
        The username of the SQL user account.
    .PARAMETER Database
        The database name for the customer data.
    .PARAMETER HAGListener
        The High Availability Group listener for the SQL instance to be used.
    .PARAMETER SQLInstance
        The SQL Instance name.
    .PARAMETER OutPath
        The location of the output file which will contain the encrypted connection string.
    .PARAMETER CertificateFilePath
        The location of the certificate with the public key which should be used to encypt the connection string.
    .EXAMPLE
        New-ConnectionString -SQLUsername sql_username -Database TC_Data -HAGListener REK-SQLAVGR01 -SQLInstance SERVER_001 -CertificateFilePath C:\certs\TC_FirmTest1_Cert.cer -OutPath C:\certs\encryptedConnectionString.txt
        This example will create the connection string and encrypt it using the public key of the specified certificate. You will get a prompt to enter the password 
        once the function is called.
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 23/11/2016 16:08
#>

    param(
        [Parameter(Mandatory=$true)][string]$SQLUsername,
        [Parameter(Mandatory=$true)][string]$Database,
        [Parameter(Mandatory=$true)][string]$HAGListener,
        [Parameter(Mandatory=$true)][string]$SQLInstance,
        [Parameter(Mandatory=$true)][string]$OutPath,
        [Parameter(Mandatory=$true)][string]$CertificateFilePath
    )

    # Get the password used for the SQL user account for the TC database and save in clear text (this is needed for for the connection string).
    Get-PasswordConfirmation -Message "Enter the password for the SQL User account" -outVarName SQLPassword
    $connectionString = "Data Source=$HAGListener\$SQLInstance;Initial Catalog=$Database;User ID=$SQLUsername;Password=$SQLPassword;Persist Security Info=True;"
    New-StringEncrypt -ClearText $connectionString -PublicCertFilePath $CertificateFilePath -OutPath $OutPath
    Remove-Variable connectionString -Force

}

#################################################### Add-AWSCredentials ############################################################

Function Add-AWSCredentials {

<#
    .SYNOPSIS
        This function will ask for the AWS IAM user credentials which will be used to retrieve the connection string from an AWS S3 
        bucket.
    .DESCRIPTION
        This function will ask for the AWS connection details from the customer. The Access ID and the secret Access Key is asked for 
        as a secure string so that the text isn't seen on screen. These details are then encrypted using the public key of the specified 
        certificate. The output is saved to the specified location entered in the OutPath parameter.
    .PARAMETER CertificateFilePath
        The certificate with the public key which will be used to encrypt the Access ID and Secret Access Key
    .PARAMETER OutPath
        The location for the file which will contain the encypted AWS credentials.
    .EXAMPLE
        Add-AWSCredentials -AccessUserID accessID -CertificateFilePath C:\certs\TC_FirmTest1_Cert.cer -OutPath C:\certs\AWSCredentials.txt
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 24/11/2016 10:16
#>

    param(
        [Parameter(Position=1, Mandatory=$true)][string]$CertificateFilePath,
        [Parameter(Position=2, Mandatory=$true)][string]$OutPath
    )

    Get-PasswordConfirmation -Message "Enter the Access Key for the AWS IAM account" -outVarName AccessUserID
    Get-PasswordConfirmation -Message "Enter the Secret Access Key for the AWS IAM account" -outVarName secretAccessKey

    $json = '{ "accessKey":"' + $AccessUserID + '", "secretAccessKey":"' + $secretAccessKey + '" }'
    New-StringEncrypt -ClearText $json -PublicCertFilePath $CertificateFilePath -OutPath $OutPath
    Remove-Variable json -Force

}

#################################################### Get-DecryptedString ###########################################################

Function Get-DecryptedString {

<#
    .SYNOPSIS
        This function will decrypt strings using a certificate file with the private key. 
    .DESCRIPTION
        This function is used to decrypt data which has been encrypted using a certificate with a public key. It uses the private key
        of a specified certificate file to decrypt data, as long as the correct password is used to decrypt the certificate file itself.
        The output is displayed in yellow text to the console.
    .PARAMETER CertificateFile
        The path to the certificate which contains the private key.
    .PARAMETER EncryptedFilePath
        The path to the file which contains the encrpyted data.
    .PARAMETER CertificatePasswordPath
        The path to the text file which contains the certificate password. If this parameter is not used, then the password is prompted for
        on the console.
    .PARAMETER OutVarName
        The global variable to be used to hold the AWS credentials in memory.
    .EXAMPLE
        Get-DecryptedString -CertificatePath C:\certs\TC_FirmTest1_Cert.pfx -EncryptedFilePath C:\certs\AWSCredentials.txt -CertificatePasswordPath C:\certPassword.txt
        This example will decrypt the contents of C:\certs\AWSCredentials.txt using the TC_FirmTest1_Cert.pfx with the password contained 
        in C:\certPassword.txt
    .EXAMPLE
        Get-DecryptedString -CertificatePath C:\certs\TC_FirmTest1_Cert.pfx -EncryptedFilePath C:\certs\AWSCredentials.txt
        This example will decrypt the contents of C:\certs\AWSCredentials.txt using the TC_FirmTest1_Cert.pfx and will prompt the user for the 
        certificate password.
    .EXAMPLE
        Get-DecryptedString -CertificatePath C:\certs\TC_FirmTest1_Cert.pfx -EncryptedFilePath C:\certs\AWSCredentials.txt -OutVarName AWSCredentials
        This example will decrypt the contents of C:\certs\AWSCredentials.txt using the TC_FirmTest1_Cert.pfx and will prompt for the user for 
        certificate password. It will save the password to a global variable called $AWSCredentials.
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 24/11/2016 10:41
#>

    param(
        [Parameter(Mandatory=$true)][string]$CertificatePath,
        [Parameter(Mandatory=$true)][string]$EncryptedFilePath,
        [string]$CertificatePasswordPath,
        [string]$outVarName
    )

    if ($CertificatePasswordPath) {

        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, (get-content $CertificatePasswordPath))

    } else {

        Get-PasswordConfirmation -Message "Enter the password for the certificate" -outVarName CertificatePassword
        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword)

    }

    if ($outVarName) {

        [System.Security.Cryptography.RSACryptoServiceProvider]$privKey = $thing.PrivateKey
        $EncryptedBytes = [Convert]::FromBase64String((get-content $EncryptedFilePath))
        $DecryptedString = [System.Text.Encoding]::UTF8.GetString($Certificate.PrivateKey.Decrypt($EncryptedBytes,$true))
        New-Variable -name $outVarName -Value $DecryptedString -Scope Global -Force

    } else {

        [System.Security.Cryptography.RSACryptoServiceProvider]$privKey = $thing.PrivateKey
        $EncryptedBytes = [Convert]::FromBase64String((get-content $EncryptedFilePath))
        $DecryptedString = [System.Text.Encoding]::UTF8.GetString($Certificate.PrivateKey.Decrypt($EncryptedBytes,$true))
        write-host $DecryptedString -ForegroundColor Yellow

    }

}

#################################################### Invoke-KMSEncryptText #########################################################

Function Invoke-KMSEncryptText {

<#
    .SYNOPSIS
        This function will encrypt strings using an AWS KMS key. 
    .DESCRIPTION
        This function will encrypt clear text strings of data using an Amazon Web Services key from their KMS service. It relies upon the 
        awspowershell module as it uses the Invoke-KMSEncrypt commandlet. This function includes checks to confirm that the module is
        installed and can be seen in the list of imported modules.
        In order to using the Invoke-KMSEncrypt commandlet included in the awspowershell modules, the clear text needs to be formatted into
        a byte array and then injected into a memory stream. This is then passed as one of the parameters to the Invoke-KMSEncrypt command,
        along with other parameters such as the IAM user details, key ID and AWS region where the key exists.
        The function relies upon the Get-PasswordConfirmation function to obtain the AWS Access Key ID and Secret Access Key details and the
        Test-PathCheck function to check the certificate file and password paths entered.
    .PARAMETER ClearText
        The data you wish to encrypt.
    .PARAMETER keyID
        The KeyID of the KMS key in AWS.
    .PARAMETER Region
        The region where the KMS key exists.
    .PARAMETER OutFilePath
        The file path of the file for the encrypted data.
    .EXAMPLE
        Invoke-KMSEncryptText -ClearText "this is a secret"  -keyID "a9963648-5589-4d91-a1f4-473c37f1f55c" -Region "eu-west-1" -OutFilePath c:\certs\AWSkmsEncryptedData.txt
        This example will encrypt the text "this is a secret" using the specified KMS key in the Ireland region
    .EXAMPLE
        Invoke-KMSEncryptText -ClearText (get-content C:\certs\AWSCredentials.txt)  -keyID "a9963648-5589-4d91-a1f4-473c37f1f55c" -Region "eu-west-1" -OutFilePath c:\certs\AWSkmsEncryptedData.txt
        This example will encrypt the contents of c:\certs\AWSCrednetials.txt using the specified KMS key in the Ireland region
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 24/11/2016 11:13
#>

    param(
        [Parameter(Mandatory=$true)][string]$ClearText,
        [Parameter(Mandatory=$true)][string]$keyID,
        [Parameter(Mandatory=$true)][string]$Region,
        [Parameter(Mandatory=$true)][string]$OutFilePath,
        [string]$AWSEncryptedCredentialFilePath
    )

    try {
    
        import-module awspowershell -ErrorAction stop

        if (get-module -name awspowershell -ErrorAction stop) {

            if ($AWSEncryptedCredentialFilePath) {

                Write-Host "Please enter the following information in order to decrypt the AWS Credentials" -ForegroundColor Yellow
                Test-PathCheck -message "Enter the path where the certificate with the private key resides" -OutVarName certPath
                Test-PathCheck -message "Enter the path where the certificate password resides" -OutVarName certPwdPath

                Get-DecryptedString -CertificatePath $certPath -EncryptedFilePath $AWSEncryptedCredentialFilePath -CertificatePasswordPath $certPwdPath -outVarName json

                $AccessKey = ($json | ConvertFrom-Json).accessKey
                $SecretKey = ($json | ConvertFrom-Json).secretAccessKey

            } else {
            
                Get-PasswordConfirmation -Message "Enter the AWS Access Key" -outVarName AccessKey
                Get-PasswordConfirmation -Message "Enter the AWS Secret Key" -outVarName SecretKey
            
            }

            [byte[]]$byteArray = [System.Text.Encoding]::UTF8.GetBytes($ClearText)
            $memoryStream = New-Object System.IO.MemoryStream($byteArray,0,$byteArray.Length)
            $Arguments = @{Plaintext=$memoryStream; KeyId=$keyID; Region=$Region; AccessKey=$AccessKey; SecretKey=$SecretKey}

            try {
            
                $encryptedMemoryStream = Invoke-KMSEncrypt @Arguments
                $base64encrypted = [System.Convert]::ToBase64String($encryptedMemoryStream.CiphertextBlob.ToArray())

                $base64encrypted | Out-File $OutFilePath

            } catch {

                write-warning "Could not access the KMS service at this time. Confirm the AWS account you've used has been granted access to use the KMS key you've specified."

            }

        } else {

            write-warning "The awspowershell module doesn't seem to be imported. Try 'Import-Module awspowershell' followed by 'Get-Module' to confirm it can be imported"

        }
        
    } catch {
    
        write-warning "Could not import the awspowershell module. Please ensure this is installed first"
        
    }

}


#################################################### Invoke-KMSDecryptText #########################################################

Function Invoke-KMSDecryptText {

<#
    .SYNOPSIS
        This function will decrypt strings which have been encrypted using an AWS KMS key. 
    .DESCRIPTION
        This function will decrpyt strings which have been encrypted using an AWS KMS key. It uses the Invoke-KMSDecrypt commandlet
        which is included in the awspowershell module therefore the awspowershell module needs to be installed. The function will 
        attempt to import the module and confirm that it is listed for use. If it can't import or see the module, it will throw an
        error and not run.
        AWS KMS returns the decrypted data as a memory stream so a memorystream object is constructed to receive this data back.
        The KMS key which was used to encrypt the data is included in the encrypted text, therefore the KeyID does not need to be
        specified with this function. You only need the region where the key exists and the Access Key ID/Secret Access Key details
        of an IAM account which has access to use the KMS key.
        The function relies upon the Get-PasswordConfirmation function to obtain the AWS Access Key ID and Secret Access Key details
        and the Test-PathCheck function to check the certificate file and password paths entered.
    .PARAMETER EncryptedText
        The encrypted text you wish to decrypt.
    .PARAMETER Region
        The region of the KMS key you wish to use.
    .PARAMETER AWSEncryptedCredentialFile
        The path where the Encrypted AWS Credentials reside. This will prompt further input for the path of the certificate with the
        private key (and it's password) which was used to encrypt the AWS credentials.
    .EXAMPLE
        $EncryptedTextTest = "AQECAHgWxFiIshn1Osc8/9PFKtxUCorpkkayMvMXzwvYzhVzDQAAAHQwcgYJKoZIhvcNAQcGoGUwYwIBADBeBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDPKTGRvC8g6MfANaDAIBEIAx/d0Khs5niSvZkVaz1VAwE6DTYPfjuy2596va+hQJWc43F3zFB4X/KhwvHIeCUBfUqQ=="
        Invoke-KMSDecryptText -EncryptedText $EncryptedTextTest  -keyID "a9963648-5589-4d91-a1f4-473c37f1f55c" -Region "eu-west-1"
        This example will decrypt the value of $EncryptedTextTest using the specified KMS key in the Ireland region
    .EXAMPLE
        Invoke-KMSDecryptText -EncryptedText (get-content C:\certs\AWSCredentials.txt)  -keyID "a9963648-5589-4d91-a1f4-473c37f1f55c" -Region "eu-west-1"
        This example will decrypt the contents of c:\certs\AWSCrednetials.txt using the specified KMS key in the Ireland region
    .EXAMPLE
        Invoke-KMSDecryptText -EncryptedText (get-content c:\certs\AWSkmsEncryptedData.txt) -Region "eu-west-1" -AWSEncryptedCredentialFilePath C:\certs\AWSCredentials.txt
        This example will decrypt the file AWSkmsEncryptedData.txt (which is data which has been encrypted using an AWS KMS key). It will use the credentials from the
        AWSCredentials file (which have been encrypted using the public key of a certificate file). This command will prompt for further input for the path
        of the certificate's .pfx file and the password it has been encrypted with.
    .NOTES
        AUTHOR: Edward Snow
        LASTEDIT: 24/11/2016 11:11
#>

    param(
        [Parameter(Mandatory=$true)][string]$EncryptedText,
        [Parameter(Mandatory=$true)][string]$Region,
        [string]$AWSEncryptedCredentialFilePath
    )

    try {
    
        import-module awspowershell -ErrorAction stop

        if (get-module -name awspowershell -ErrorAction stop) {

            if ($AWSEncryptedCredentialFilePath) {

                Write-Host "Please enter the following information in order to decrypt the AWS Credentials" -ForegroundColor Yellow
                Test-PathCheck -message "Enter the path where the certificate with the private key resides" -OutVarName certPath
                Test-PathCheck -message "Enter the path where the certificate password resides" -OutVarName certPwdPath

                Get-DecryptedString -CertificatePath $certPath -EncryptedFilePath $AWSEncryptedCredentialFilePath -CertificatePasswordPath $certPwdPath -outVarName json

                $AccessKey = ($json | ConvertFrom-Json).accessKey
                $SecretKey = ($json | ConvertFrom-Json).secretAccessKey

            } else {

                Get-PasswordConfirmation -Message "Enter the AWS Access Key" -outVarName AccessKey
                Get-PasswordConfirmation -Message "Enter the AWS Secret Key" -outVarName SecretKey

            }

            $encryptedBytes = [System.Convert]::FromBase64String($EncryptedText)
            $encryptedMemoryStreamToDecrypt = New-Object System.IO.MemoryStream($encryptedBytes,0,$encryptedBytes.Length)
            $Arguments = @{CiphertextBlob=$encryptedMemoryStreamToDecrypt; Region=$Region; AccessKey=$AccessKey; SecretKey=$SecretKey}

            try {

                $decryptedMemoryStream = Invoke-KMSDecrypt @Arguments
                $plainText = [System.Text.Encoding]::UTF8.GetString($decryptedMemoryStream.Plaintext.ToArray())

                write-host $plainText -ForegroundColor Yellow

            } catch {

                write-warning "Could not access the KMS service at this time. Confirm the AWS account you've used has been granted access to use the KMS key you've specified."

            }

        } else {

            write-warning "The awspowershell module doesn't seem to be imported. Try 'Import-Module awspowershell' followed by 'Get-Module' to confirm it can be imported."

        }
        
    } catch {
    
        write-warning "Could not import the awspowershell module. Please ensure this is installed first."
        
    }

}
