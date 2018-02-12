#requires -Version 5

# Suppression of this PSSA rule allowed in examples
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param()

Configuration OM
{
    Import-DscResource -Module xCredSSP
    Import-DscResource -Module xSQLServer
    Import-DscResource -Module xSCOM

    # Set role and instance variables
    $Roles = $AllNodes.Roles | Sort-Object -Unique
    foreach ($Role in $Roles) {
        $Servers = @($AllNodes.Where{$_.Roles | Where-Object {$_ -eq $Role}}.NodeName)
        Set-Variable -Name ($Role.Replace(" ", "").Replace(".", "") + "s") -Value $Servers
        if ($Servers.Count -eq 1) {
            Set-Variable -Name ($Role.Replace(" ", "").Replace(".", "")) -Value $Servers[0]
            if (
                $Role.Contains("Database") -or
                $Role.Contains("Datawarehouse") -or
                $Role.Contains("Reporting") -or
                $Role.Contains("Analysis") -or
                $Role.Contains("Integration")
            ) {
                $Instance = $AllNodes.Where{$_.NodeName -eq $Servers[0]}.SQLServers.Where{$_.Roles | Where-Object {$_ -eq $Role}}.InstanceName
                Set-Variable -Name ($Role.Replace(" ", "").Replace(".", "").Replace("Server", "Instance")) -Value $Instance
            }
        }
    }

    Node $AllNodes.NodeName
    {
        # Set LCM to reboot if needed
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        write-verbose "LCM"

        # Install .NET Framework 3.5 on SQL and Web Console nodes
        if (
            ($Node.Roles -contains "System Center Operations Manager Database Server") -or
            ($Node.Roles -contains "System Center Operations Manager Datawarehouse Server") -or
            ($Node.Roles -contains "System Center Operations Manager Reporting Server") -or
            ($Node.Roles -contains "System Center Operations Manager Web Console Server") -or
            ($Node.Roles -contains "SQL Server  Management Tools")
        ) {
            WindowsFeature "NET-Framework-Core" {
                Ensure = "Present"
                Name   = "NET-Framework-Core"
                Source = $Node.SourcePath + "\WindowsServerR2\sources\sxs"
            }
        }

        # Install IIS on Web Console Servers
        if ($Node.Roles -contains "System Center Operations Manager Web Console Server") {
            WindowsFeature "Web-WebServer" {
                Ensure = "Present"
                Name   = "Web-WebServer"
            }

            WindowsFeature "Web-Request-Monitor" {
                Ensure = "Present"
                Name   = "Web-Request-Monitor"
            }

            WindowsFeature "Web-Windows-Auth" {
                Ensure = "Present"
                Name   = "Web-Windows-Auth"
            }

            WindowsFeature "Web-Asp-Net" {
                Ensure = "Present"
                Name   = "Web-Asp-Net"
            }

            WindowsFeature "Web-Asp-Net45" {
                Ensure = "Present"
                Name   = "Web-Asp-Net45"
            }

            WindowsFeature "NET-WCF-HTTP-Activation45" {
                Ensure = "Present"
                Name   = "NET-WCF-HTTP-Activation45"
            }

            WindowsFeature "Web-Mgmt-Console" {
                Ensure = "Present"
                Name   = "Web-Mgmt-Console"
            }

            WindowsFeature "Web-Metabase" {
                Ensure = "Present"
                Name   = "Web-Metabase"
            }
        }

        write-verbose "Features"

        # Install SQL Instances
        if (
            ($Node.Roles -contains "System Center Operations Manager Database Server") -or
            ($Node.Roles -contains "System Center Operations Manager Datawarehouse Server") -or
            ($Node.Roles -contains "System Center Operations Manager Reporting Server")
        ) {
            foreach ($SQLServer in $Node.SQLServers) {
                $SQLInstanceName = $SQLServer.InstanceName

                $Features = ""
                if (
                    (
                        ($Node.Roles -contains "System Center Operations Manager Database Server") -and
                        ($SystemCenterR2OperationsManagerDatabaseInstance -eq $SQLInstanceName)
                    ) -or
                    (
                        ($Node.Roles -contains "System Center Operations Manager Datawarehouse Server") -and
                        ($SystemCenterR2OperationsManagerDatawarehouseInstance -eq $SQLInstanceName)
                    ) -or
                    (
                        ($Node.Roles -contains "System Center Operations Manager Reporting Server") -and
                        ($Node.SQLServers.InstanceName -eq $SQLInstanceName)
                    )
                ) {
                    $Features += "SQLENGINE,"
                }
                if (
                    (
                        ($Node.Roles -contains "System Center Operations Manager Database Server") -and
                        ($SystemCenterR2OperationsManagerDatabaseInstance -eq $SQLInstanceName)
                    ) -or
                    (
                        ($SystemCenterR2OperationsManagerDatawarehouseInstance -eq $SQLInstanceName)
                    )
                ) {
                    $Features += "FULLTEXT,"
                }
                if ($Node.Roles -contains "System Center Operations Manager Reporting Server" -and
                    (
                        ($Node.NodeName -eq $Node.NodeName) -and
                        ($Node.SQLServers.InstanceName -eq $SQLInstanceName)
                    )
                ) {
                    $Features += "RS,"
                }
                if ($Node.Roles -contains "System Center Operations Manager Reporting Server" -and
                    (
                        ($Node.NodeName -eq $Node.NodeName) -and
                        ($Node.SQLServers.InstanceName -eq $SQLInstanceName)
                    )
                ) {
                    $Features += "AS,"
                }
                $Features = $Features.Trim(",")

                if ($Features -ne "") {
                    xSqlServerSetup ($Node.NodeName + $SQLInstanceName) {
                        DependsOn            = "[WindowsFeature]NET-Framework-Core"
                        SourcePath           = (join-path $Node.SourcePath 'SQL')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        InstanceName         = $SQLInstanceName
                        Features             = $Features
                        SQLSysAdminAccounts  = $Node.AdminAccount
                    }
                    write-verbose "sqlsetup"

                    xSqlServerFirewall ($Node.NodeName + $SQLInstanceName) {
                        DependsOn    = ("[xSqlServerSetup]" + $Node.NodeName + $SQLInstanceName)
                        SourcePath   = (join-path $Node.SourcePath 'SQL')
                        InstanceName = $SQLInstanceName
                        Features     = $Features
                    }
                    write-verbose "sql firewall"
                }
            }
        }

        # Install SQL Management Tools
        if ($Node.Roles -contains "SQL Server  Management Tools") {
            xSqlServerSetup "SQLMT" {
                DependsOn            = "[WindowsFeature]NET-Framework-Core"
                SourcePath           = (join-path $Node.SourcePath 'SQLMT')
                PsDscRunAsCredential = $Node.InstallerServiceAccount
                InstanceName         = "NULL"
                Features             = "SSMS,ADV_SSMS"
            }
            write-verbose "sqlsetup"
        }
        write-verbose "before reportviewer"
        # Install Report Viewer  on Web Console Servers and Consoles
        if (
            ($Node.Roles -contains "System Center Operations Manager Web Console Server") -or
            ($Node.Roles -contains "System Center Operations Manager Console")
        ) {
            if ($Node.SQLServerSystemCLRTypes) {
                $SQLServerSystemCLRTypes = (Join-Path -Path $Node.SQLServerSystemCLRTypes -ChildPath "SQLSysClrTypes.msi")
            }
            else {
                $SQLServerSystemCLRTypes = "\Prerequisites\SQLCLR\SQLSysClrTypes.msi"
            }
            write-verbose "clr"
            Package "SQLServerSystemCLRTypes" {
                Ensure     = "Present"
                Name       = "Microsoft System CLR Types for SQL Server  (x64)"
                ProductId  = ""
                Path       = (Join-Path -Path $Node.SourcePath -ChildPath $SQLServerSystemCLRTypes)
                Arguments  = "ALLUSERS=2"
                Credential = $Node.InstallerServiceAccount
            }


            if ($Node.ReportViewerRedistributable) {
                $ReportViewerRedistributable = (Join-Path -Path $Node.SQLServerSystemCLRTypes -ChildPath "ReportViewer.msi.msi")
            }
            else {
                $ReportViewerRedistributable = "\Prerequisites\RV\ReportViewer.msi"
            }
            Package "ReportViewerRedistributable" {
                DependsOn  = "[Package]SQLServerSystemCLRTypes"
                Ensure     = "Present"
                Name       = "Microsoft Report Viewer  Runtime"
                ProductID  = ""
                Path       = (Join-Path -Path $Node.SourcePath -ChildPath $ReportViewerRedistributable)
                Arguments  = "ALLUSERS=2"
                Credential = $Node.InstallerServiceAccount
            }
            write-verbose "reportviewer"
        }
        write-verbose "before admins"
        # Add service accounts to admins on Management Servers
        if ($Node.Roles -contains "System Center Operations Manager Management Server") {
            Group "Administrators" {
                GroupName        = "Administrators"
                MembersToInclude = @(
                    $Node.SystemCenterOperationsManagerActionAccount.UserName,
                    $Node.SystemCenterOperationsManagerDASAccount.UserName
                )
                Credential       = $Node.InstallerServiceAccount
            }
            write-verbose "admins"
        }
        write-verbose "before management"
        # Install first Management Server
        if (($Nodes | ? {$_.Roles -eq "System Center Operations Manager Management Server"} | select -first 1).NodeName -eq $Node.NodeName) {
            # Enable CredSSP - required for ProductKey PS cmdlet
            xCredSSP "Server" {
                Ensure = "Present"
                Role   = "Server"
            }

            xCredSSP "Client" {
                Ensure            = "Present"
                Role              = "Client"
                DelegateComputers = $Node.NodeName
            }
            write-verbose "CredSSP"

            # Create DependsOn for first Management Server
            $DependsOn = @(
                "[xCredSSP]Server",
                "[xCredSSP]Client",
                "[Group]Administrators"
            )

            # Install first Management Server
            xSCOMManagementServerSetup "OMMS" {
                DependsOn             = $DependsOn
                Ensure                = "Present"
                SourcePath            = (join-path $Node.SourcePath 'SCOM')
                SetupCredential       = $Node.InstallerServiceAccount
                ProductKey            = $Node.SystemCenterProductKey
                ManagementGroupName   = "OM_MGT"
                FirstManagementServer = $true
                ActionAccount         = $Node.SystemCenterOperationsManagerActionAccount
                DASAccount            = $Node.SystemCenterOperationsManagerDASAccount
                DataReader            = $Node.SystemCenterOperationsManagerDataReader
                DataWriter            = $Node.SystemCenterOperationsManagerDataWriter
                SqlServerInstance     = ($SystemCenterR2OperationsManagerDatabaseServer + "\" + $SystemCenterR2OperationsManagerDatabaseInstance)
                DwSqlServerInstance   = ($SystemCenterR2OperationsManagerDatawarehouseServer + "\" + $SystemCenterR2OperationsManagerDatawarehouseInstance)
            }
            write-verbose "scominstall"
        }
        write-verbose "before wait for mgmt"
        # Wait for first Management Server on other Management Servers
        # and Reporting and Web Console server, if they are not on a Management Server
        if (
            (
                ($Node.Roles -contains "System Center Operations Manager Management Server") -and
                (($Nodes | ? {$_.Roles -eq "System Center Operations Manager Management Server"} | select -first 1).NodeName -ne $Node.NodeName)
            ) -or
            (
                ($Node.Roles -contains "System Center Operations Manager Reporting Server") -and
                (!($Node.Roles -contains "System Center Operations Manager Management Server"))
            ) -or
            (
                ($Node.Roles -contains "System Center Operations Manager Web Console Server") -and
                (!($Node.Roles -contains "System Center Operations Manager Management Server"))
            )
        ) {
            WaitForAll "OMMS" {
                NodeName             = ($Nodes | ? {$_.Roles -eq "System Center Operations Manager Management Server"} | select -first 1).NodeName
                ResourceName         = "[xSCOMManagementServerSetup]OMMS"
                PsDscRunAsCredential = $Node.InstallerServiceAccount
                RetryCount           = 1440
                RetryIntervalSec     = 5
            }
            write-verbose "wait scom install"
        }
        write-verbose "before othermgmt"
        # Install other Management Servers
        if (
            ($Node.Roles -contains "System Center Operations Manager Management Server") -and
            (($Nodes | ? {$_.Roles -eq "System Center Operations Manager Management Server"} | select -first 1).NodeName -ne $Node.NodeName)
        ) {
            xSCOMManagementServerSetup "OMMS" {
                DependsOn             = @(
                    "[Group]Administrators",
                    "[WaitForAll]OMMS"
                )
                Ensure                = "Present"
                SourcePath            = (join-path $Node.SourcePath 'SCOM')
                SetupCredential       = $Node.InstallerServiceAccount
                ManagementGroupName   = "OM_MGT"
                FirstManagementServer = $false
                ActionAccount         = $Node.SystemCenterOperationsManagerActionAccount
                DASAccount            = $Node.SystemCenterOperationsManagerDASAccount
                DataReader            = $Node.SystemCenterOperationsManagerDataReader
                DataWriter            = $Node.SystemCenterOperationsManagerDataWriter
                SqlServerInstance     = ($SystemCenterR2OperationsManagerDatabaseServer + "\" + $SystemCenterR2OperationsManagerDatabaseInstance)
                DwSqlServerInstance   = ($SystemCenterR2OperationsManagerDatawarehouseServer + "\" + $SystemCenterR2OperationsManagerDatawarehouseInstance)
            }
            write-verbose "scominstall"
        }
        write-verbose "before reporting"
        # Install Reporting Server
        if ($Node.Roles -contains "System Center Operations Manager Reporting Server") {
            # If this is a Management Server, depend on itself
            # else wait for the first Management Server
            if ($Node.Roles -contains "System Center Operations Manager Management Server") {
                $DependsOn = "[xSCOMManagementServerSetup]OMMS"
            }
            else {
                $DependsOn = "[WaitForAll]OMMS"
            }

            xSCOMReportingServerSetup "OMRS" {
                DependsOn        = $DependsOn
                Ensure           = "Present"
                SourcePath       = (join-path $Node.SourcePath 'SCOM')
                SetupCredential  = $Node.InstallerServiceAccount
                ManagementServer = ($Nodes | ? {$_.Roles -eq "System Center Operations Manager Management Server"} | select -first 1).NodeName
                SRSInstance      = ($Node.NodeName + "\" + $Node.SQLServers.InstanceName)
                DataReader       = $Node.SystemCenterOperationsManagerDataReader
            }
            write-verbose "scom reporting"
        }
        write-verbose "before webconsole"
        # Install Web Console Servers
        if ($Node.Roles -contains "System Center Operations Manager Web Console Server") {
            $DependsOn = @(
                "[WindowsFeature]NET-Framework-Core",
                "[WindowsFeature]Web-WebServer",
                "[WindowsFeature]Web-Request-Monitor",
                "[WindowsFeature]Web-Windows-Auth",
                "[WindowsFeature]Web-Asp-Net",
                "[WindowsFeature]Web-Asp-Net45",
                "[WindowsFeature]NET-WCF-HTTP-Activation45",
                "[WindowsFeature]Web-Mgmt-Console",
                "[WindowsFeature]Web-Metabase",
                "[Package]SQLServerSystemCLRTypes",
                "[Package]ReportViewerRedistributable"
            )
            # If this is a Management Server, depend on itself
            # else wait for the first Management Server
            if ($Node.Roles -contains "System Center Operations Manager Management Server") {
                $DependsOn += @("[xSCOMManagementServerSetup]OMMS")
            }
            else {
                $DependsOn += @("[WaitForAll]OMMS")
            }
            xSCOMWebConsoleServerSetup "OMWC" {
                DependsOn        = $DependsOn
                Ensure           = "Present"
                SourcePath       = (join-path $Node.SourcePath 'SCOM')
                SetupCredential  = $Node.InstallerServiceAccount
                ManagementServer = ($Nodes | ? {$_.Roles -eq "System Center Operations Manager Management Server"} | select -first 1).NodeName
            }
            write-verbose "scomweb"
        }
        write-verbose "before console"
        # Install Consoles
        if ($Node.Roles -contains "System Center Operations Manager Console") {
            xSCOMConsoleSetup "OMC" {
                DependsOn       = @(
                    "[Package]SQLServerSystemCLRTypes",
                    "[Package]ReportViewerRedistributable"
                )
                Ensure          = "Present"
                SourcePath      = (join-path $Node.SourcePath 'SCOM')
                SetupCredential = $Node.InstallerServiceAccount
            }
            write-verbose "scom console"
        }
    }
}

$SecurePassword = ConvertTo-SecureString -String "Welome01" -AsPlainText -Force
$InstallerServiceAccount = New-Object System.Management.Automation.PSCredential ("MGT\!Installer", $SecurePassword)
$LocalSystemAccount = New-Object System.Management.Automation.PSCredential ("SYSTEM", $SecurePassword)
$SystemCenterOperationsManagerActionAccount = New-Object System.Management.Automation.PSCredential ("MGT\!om_saa", $SecurePassword)
$SystemCenterOperationsManagerDASAccount = New-Object System.Management.Automation.PSCredential ("MGT\!om_das", $SecurePassword)
$SystemCenterOperationsManagerDataReader = New-Object System.Management.Automation.PSCredential ("MGT\!om_dra", $SecurePassword)
$SystemCenterOperationsManagerDataWriter = New-Object System.Management.Automation.PSCredential ("MGT\!om_dwa", $SecurePassword)

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                                   = "*"
            PSDscAllowPlainTextPassword                = $true

            SourcePath                                 = "C:\Source\"
            InstallerServiceAccount                    = $InstallerServiceAccount
            LocalSystemAccount                         = $LocalSystemAccount

            AdminAccount                               = "MGT\Administrator"

            SystemCenterOperationsManagerActionAccount = $SystemCenterOperationsManagerActionAccount
            SystemCenterOperationsManagerDASAccount    = $SystemCenterOperationsManagerDASAccount
            SystemCenterOperationsManagerDataReader    = $SystemCenterOperationsManagerDataReader
            SystemCenterOperationsManagerDataWriter    = $SystemCenterOperationsManagerDataWriter
        }
        @{
            NodeName   = "OM1.mgt.local"
            Roles      = @(
                "System Center Operations Manager Database Server",
                "System Center Operations Manager Datawarehouse Server",
                "System Center Operations Manager Reporting Server",
                "System Center Operations Manager Management Server",
                "System Center Operations Manager Web Console Server",
                "System Center Operations Manager Console",
                "SQL Server  Management Tools"
            )
            SQLServers = @(
                @{
                    Roles        = @(
                        "System Center Operations Manager Database Server",
                        "System Center Operations Manager Datawarehouse Server",
                        "System Center Operations Manager Reporting Server"
                    )
                    InstanceName = "MSSQLSERVER"
                }
            )
        }
    )
}

foreach ($Node in $ConfigurationData.AllNodes) {
    if ($Node.NodeName -ne "*") {
        Start-Process -FilePath "robocopy.exe" -ArgumentList ("`"C:\Program Files\WindowsPowerShell\Modules`" `"\\" + $Node.NodeName + "\c$\Program Files\WindowsPowerShell\Modules`" /e /purge /xf") -NoNewWindow -Wait
    }
}

OM -ConfigurationData $ConfigurationData
Set-DscLocalConfigurationManager -Path .\OM -Verbose
Start-DscConfiguration -Path .\OM -Verbose -Wait -Force
