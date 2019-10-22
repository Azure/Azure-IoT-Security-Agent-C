#!/bin/bash

_userName="asciotagent"
_serviceTemplateName="ASCIoTAgent.service"
_systemServiceFileLocation="/etc/systemd/system"
_targetDirectory="/var/ASCIoTAgent"
_execName="ASCIoTAgent"
_scriptDir=
_mode="none"
_omsBaselineExecutablePath="https://ascforiot.blob.core.windows.net/public/"
_omsBaselineX64="omsbaseline-linux-amd64"
_omsBaselineI386="omsbaseline-linux-386"
_omsBaselineARMv7="omsbaseline-linux-arm-v7"
_omsAudits="oms_audits.xml"
_omsBaseline="omsbaseline"
_identity=
_authenticationMethod=
_filePath=
_deviceId=
_hostName=

usage()
{
    scriptName=`basename "$0"`

    echo "Utility script for installing and uninstalling the agent."
    echo ""
    echo "Usage:"
    echo "  $scriptName -i -aui <Device | SecurityModule> -aum <authentication method> -f <file path> -hn <host name> -di <device id>"
    echo "  $scriptName -u"
    echo "  $scriptName -h"
    echo ""
    echo "Options:"
    echo " -i   --install                    Install the agent."
    echo " -u   --uninstall                  Uninstall the agent."
    echo " -h   --help                       Show this screen."
    echo " -aui --authentication-identity    The authentication identity used by the agent (SecurityModule or Device)."
    echo " -aum --authentication-method      The authentication method used by the agent (SymmetricKey or SelfSignedCertificate)."
    echo " -f   --file-path                  Path to a file from which data related to the authentication method should be read (the key or certificate)."
    echo " -hn  --host-name                  IoT hub's host name."
    echo " -di  --device-id                  Id of the device the agent is beind installed on (as defined in the IoT hub)."
}

wgetAndExitOnFail(){
    wget "$1" -O "$2"
    if [ $? -ne 0 ]; then
        echo "Couldn't donwload $1, exiting...";
        exit 1;
    fi
}

uninstallagent()
{
    echo uninstalling agent

    #stop the daemon
    systemctl stop $_serviceTemplateName

    #disable the service
    systemctl disable $_serviceTemplateName

    #remove the agent files
    rm -rf $_targetDirectory

    #remove the service user
    deluser --remove-home --remove-all-files $_userName

    #remove the service configuration
    rm $_systemServiceFileLocation/$_serviceTemplateName

    echo agent uninstallation finished
}

installagent()
{
    #install dependencies
    echo installing agent dependencies
    apt-get update -y && apt-get install -y \
        auditd \
        uuid-runtime \
        libcurl4-openssl-dev

    echo installing agent

    #add the service user
    echo creating service user
    adduser --disabled-login --gecos 'ASC IoT Agent' $_userName
    usermod -a -G sudo $_userName

    #Get oms executables according to systems architecture
    baselinePath="$_scriptDir/$_omsBaseline"

    #get oms executables:
    wgetAndExitOnFail "${_omsBaselineExecutablePath}${_omsAudits}" "$_scriptDir/$_omsAudits"

    # download omsbaseline supported architecture
	case $(uname -m) in
    'x86_64')
        wgetAndExitOnFail "${_omsBaselineExecutablePath}${_omsBaselineX64}"  $baselinePath
        ;;
    'armv7l')
		wgetAndExitOnFail "${_omsBaselineExecutablePath}${_omsBaselineARMv7}"  $baselinePath
		;;
    'i368')
        wgetAndExitOnFail "${_omsBaselineExecutablePath}${_omsBaselineI386}" $baselinePath
		;;
    *)
		echo "Not supported architecture"
        exit 1
		;;
	esac

    #populate the target directory with the agent files
    mkdir $_targetDirectory
    cp -r $_scriptDir/* $_targetDirectory

    #add connection string in app.config
    sed -i -e "s|\"Identity\" : \"[^\"]*\"|\"Identity\" : \"$_identity\"|g" $_targetDirectory/LocalConfiguration.json
    sed -i -e "s|\"AuthenticationMethod\" : \"[^\"]*\"|\"AuthenticationMethod\" : \"$_authenticationMethod\"|g" $_targetDirectory/LocalConfiguration.json
    sed -i -e "s|\"FilePath\" : \"[^\"]*\"|\"FilePath\" : \"$_filePath\"|g" $_targetDirectory/LocalConfiguration.json
    sed -i -e "s|\"DeviceId\" : \"[^\"]*\"|\"DeviceId\" : \"$_deviceId\"|g" $_targetDirectory/LocalConfiguration.json
    sed -i -e "s|\"HostName\" : \"[^\"]*\"|\"HostName\" : \"$_hostName\"|g" $_targetDirectory/LocalConfiguration.json

    #generate agentId GUID
    agentId=$(uuidgen)
    sed -i -e "s|\"AgentId\" : \"[^\"]*\"|\"AgentId\" : \"$agentId\"|g" $_targetDirectory/LocalConfiguration.json

    #make the agent user owner of the target directory
    chown -R $_userName:$_userName $_targetDirectory

    #make agent executable
    chown root $_targetDirectory/$_execName
    chmod 4755 $_targetDirectory/$_execName
    chmod +x $_targetDirectory/$_omsBaseline

    #replace variables in the service file template
    sed -e "s|{DIRECTORY}|$_targetDirectory|g" -e "s|{EXE}|$_execName|g" -e "s|{USER}|$_userName|g" -e "s|{GROUP}|$_userName|g" $_serviceTemplateName > $_systemServiceFileLocation/$_serviceTemplateName

    #reload the deamon, in case is was already installed before
    systemctl daemon-reload

    #enable the service so that it starts on boot
    systemctl enable $_serviceTemplateName

    #start the service
    systemctl start $_serviceTemplateName

    echo agent installation finished
}

validate_installation_params()
{
    shouldExit=false

    if [ -z "$_authenticationMethod" ]
    then
		echo "authentication-method not provided"
        shouldExit=true
    fi

	if [ -z "$_filePath" ]
	then
		echo "file-path not provided"
        shouldExit=true
	fi

	if [ -z "$_identity" ]
    then
		echo "authentication-identity not provided"
        shouldExit=true
	else
		if [ -z "$_hostName" ]
		then
			echo "host-name not provided"
			shouldExit=true
		fi

		if [ -z "$_deviceId" ]
		then
			echo "device-id not provided"
			shouldExit=true
		fi
	fi

    if $shouldExit
    then
        echo "cannot intall the agent, please check the validity of the supplied parameters"
        exit 1
    fi
}

setFilePath(){
	file=$1
	dir=$(pwd)
	if [[ $file == /* ]]
	then
		_filePath=$file
	else
		_filePath=$dir/$file

	fi
	if [ ! -f $_filePath ]; then
		echo "File $_filePath does not exist!";
		exit 1;
	fi
}

#parse command line arguments
while [ "$1" != "" ]; do
    case $1 in
        -aui | --authentication-identity )  shift
            if [ "$1" = "SecurityModule" ] || [ "$1" = "Device" ]; then
                _identity=$1
            else
                echo "Possible values for authentication-identity are: SecurityModule or Device"
                usage
                exit 1
            fi
                                    ;;
        -aum | --authentication-method )  shift
            if [ "$1" = "SymmetricKey" ] || [ "$1" = "SelfSignedCertificate" ]; then
                _authenticationMethod=$1
            else
                echo "Possible values for authentication-method are: SymmetricKey or SelfSignedCertificate"
                usage
                exit 1
            fi
                                    ;;
        -f | --file-path )          shift
                                    setFilePath $1
                                    ;;
		-hn | --host-name )         shift
									_hostName=$1
									;;
		-di | --device-id)          shift
									_deviceId=$1
									;;
        -u | --uninstall )          _mode="uninstall"
                                    ;;
        -i | --install )            _mode="install"
                                    ;;
        -h | --help )               usage
                                    exit
                                    ;;
        * )                         usage
                                    exit 1
    esac
    shift
done

_scriptDir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

_authenticationMethod=${_authenticationMethod/SymmetricKey/SasToken}

if [[ $_mode == "uninstall" ]]; then
    uninstallagent
elif [[ $_mode == "install" ]]; then
    validate_installation_params
    installagent
else
    usage
fi