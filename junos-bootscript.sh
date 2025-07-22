#!/bin/sh

# Remote server root directories
# tftp: /var/lib/tftpboot/
# http: /var/www/html/ 
# bootscript: /topology/project/templates/
#
# Device local directories:
# config: /var/tmp/
# firmware image: /var/tmp/
# ztp log: /var/log/

# Variables
HOSTNAME="{{Hostname}}"
REMOTE_SERVER="{{tftp_server}}"
CONFIG_FILE="{{config_file}}"
TARGET_FIRMWARE_FILE="{{firmware_file}}"
TARGET_FIRMWARE_MD5="{{firmware_file_md5}}"

CONFIG_PATH="/var/tmp/"
FIRMWARE_PATH="/var/tmp/" # Relates to the URL path used in the request system add command /ex4300

MAX_RETRIES=3
RETRY_DELAY=30  # seconds between retries
REBOOT_WAIT=10  # seconds to wait for reboot
MAX_INSTALL_TIME=600  # 10 minutes timeout for installation

LOG_FILE="/var/log/ztp-upgrade.log"

# grep version number
TARGET_VERSION=$(echo "$TARGET_FIRMWARE_FILE" | grep -o "[0-9][0-9]\.[0-9].*" | sed 's/[a-zA-Z].*//')

# Space requirements as variables instead of associative array
MIN_SPACE_REQ="536870912"
AVG_SPACE_REQ="1073741824"
SPACE_REQ_SRX4100="1395864371"
SPACE_REQ_SRX1500="751619276"
SPACE_REQ_QFX5120="1932735283"
SPACE_REQ_QFX5110="751619276"
SPACE_REQ_EX4300="268435456"
SPACE_REQ_EX4600="536870912"

# Function to get space requirement based on model
get_space_requirement() {
    case "$1" in
        *"srx4100"*) echo "$SPACE_REQ_SRX4100" ;;
        *"srx1500"*) echo "$SPACE_REQ_SRX1500" ;;
        *"qfx5120"*) echo "$SPACE_REQ_QFX5120" ;;
        *"qfx5110"*) echo "$SPACE_REQ_QFX5110" ;;
        *"ex4300"*)  echo "$SPACE_REQ_EX4300" ;;
        *"ex4600"*)  echo "$SPACE_REQ_EX4600" ;;
        *)           echo "$AVG_SPACE_REQ" ;;  # Default value
    esac
}

# Logging function
log_message() {
    LEVEL=$1
    MESSAGE=$2
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    LOG_ENTRY=""

    case "$LEVEL" in
        "DEBUG")   LOG_ENTRY="DEBUG   | $TIMESTAMP | $MESSAGE";;  # Detailed debug information
        "INFO")    LOG_ENTRY="INFO    | $TIMESTAMP | $MESSAGE";; # Normal execution messages
        "NOTICE")  LOG_ENTRY="NOTICE  | $TIMESTAMP | $MESSAGE";; # Important normal conditions
        "WARNING") LOG_ENTRY="WARNING | $TIMESTAMP | $MESSAGE";; # Warning conditions
        "ERROR")   LOG_ENTRY="ERROR   | $TIMESTAMP | $MESSAGE";; # Error conditions
        "COMMAND") LOG_ENTRY="COMMAND | $TIMESTAMP | $MESSAGE";; # CLI commands being executed
        "RESULT")  LOG_ENTRY="RESULT  | $TIMESTAMP | $MESSAGE";; # Command output/results
        *)         LOG_ENTRY="INFO    | $TIMESTAMP | $MESSAGE";; # Default to INFO
    esac

    # print to console
    echo "$LOG_ENTRY" > /dev/console
    logger -t ztp_bootscript "LOG_ENTRY" 

    # append to log file
    echo "$LOG_ENTRY" >> "$LOG_FILE" 
}


# FIRMWARE CHECKS
# Version comparison function
check_version() {
    local retry_count=0
    local success=false

    while [ $retry_count -lt $MAX_RETRIES ] && [ "$success" = false ]; do
        log_message "INFO" "Starting version check (Attempt $((retry_count + 1)) of $MAX_RETRIES)"
        
        # Try to get model and version
        if MODEL=$(cli_execute "show version | grep Model: | trim 7"); then
            log_message "RESULT" "Model: $MODEL"
            log_message "INFO" "Setting firmware file path"
            set_firmware_path "$MODEL"

            if CURRENT_VERSION=$(cli_execute "show version | grep Junos:" | sed 's/.*Junos: //' | sed 's/[a-zA-Z].*//')
            then
                log_message "RESULT" "Version: $CURRENT_VERSION"

                # Validate version information
                if [ -n "$CURRENT_VERSION" ] && [ -n "$TARGET_VERSION" ]; then
                    # Determine upgrade command based on model
                    case "$MODEL" in
                        *"ptx"*|*"jnp"*|*"mx304"*)
                            UPGRADE_CMD="request vmhost software add"
                            ;;
                        *"qfx5110"*|*"qfx5120"*)
                            UPGRADE_CMD="request system software add"
                            FORCE_HOST="force-host"
                            SKIP_VALIDATION=true
                            ;;
                        *"qfx5200"*|*"qfx5220"*)
                            UPGRADE_CMD="request system software add"
                            FORCE_HOST="force-host"
                            ;;
                        *"ex4300"*)
                            UPGRADE_CMD="request system software add"
                            SKIP_VALIDATION="no-validate"
                            ;;
                        *"ex4600"*)
                            UPGRADE_CMD="request system software add"
                            ;;
                        *"srx4100"*|*"srx1500"*)
                            UPGRADE_CMD="request system software add"
                            ;;
                        *"ex"*|*"src"*|*"mx"*)
                            UPGRADE_CMD="request system software add"
                            ;;
                        *)
                            log_message "WARNING" "Unknown model $MODEL, using default upgrade command"
                            UPGRADE_CMD="request system software add"
                            ;;
                    esac

                    log_message "INFO" "Current version: $CURRENT_VERSION, Target version: $TARGET_VERSION"
                    log_message "INFO" "Platform model: $MODEL, Using upgrade command: $UPGRADE_CMD"
                    success=true
                    break
                fi
            fi
        fi

        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            log_message "WARNING" "Version check failed, retrying in 10 seconds..."
            sleep 10
        else
            log_message "ERROR" "Version check failed after $MAX_RETRIES attempts"
            handle_error "Version check failed"
        fi
    done

    if [ "$success" = false ]; then
        handle_error "Failed to complete version check after $MAX_RETRIES attempts"
    fi
}


set_firmware_path() {
    local _MODEL="$1"
    case "$_MODEL" in
        *"ex4300"*)
            FIRMWARE_PATH="ex4300"
            ;;
        *"ex4600"*)
            FIRMWARE_PATH="ex4600"
            ;;
        *"qfx5100"*)
            FIRMWARE_PATH="qfx5100"
            ;;
        *"qfx5120"*)
            FIRMWARE_PATH="qfx5120"
            ;;
        *"srx1500"*)
            FIRMWARE_PATH="srx1500"
            ;;
        *"srx4100"*)
            FIRMWARE_PATH="srx4100"
            ;;        
    esac
    if [ -z "$FIRMWARE_PATH" ]; then
    log_message "INFO" "Firmware path unset...continue"
    fi
}

validate_version() {
    if [ -z "$CURRENT_VERSION" ] || [ -z "$TARGET_VERSION" ]; then
        handle_error "Invalid version information"
    fi
}

# Firmware verification function
verify_firmware_md5() {
    local firmware_file="$1"
    local expected_md5="$2"
    
    log_message "INFO" "Verifying firmware MD5 checksum"
    
    # Get MD5 of downloaded file using Junos CLI
    local calculated_md5
    calculated_md5=$(cli -c "file checksum md5 $firmware_file" | awk '{print $NF}')
    
    if [ -z "$calculated_md5" ]; then
        log_message "ERROR" "Failed to calculate MD5 for firmware file"
        return 1
    fi
    
    log_message "INFO" "Expected MD5: $expected_md5"
    log_message "INFO" "Calculated MD5: $calculated_md5"

    if [ "$calculated_md5" = "$expected_md5" ]; then
        log_message "NOTICE" "Firmware MD5 verification passed"
        return 0
    else
        log_message "ERROR" "Firmware MD5 verification failed"
        return 1
    fi
}

# CONFIG CHECKS
# Configuration verification function
verify_config() {
    # Check file exists and is readable
    if [ ! -f "$CONFIG_FILE" ]; then
        handle_error "Configuration file not found: $CONFIG_FILE"
        return 1
    fi
    log_message "INFO" "Configuration file exists and is readable"
    return 0
}


# SYSTEM CHECKS
JUNOS_SOFTWARE_IMAGE_REGEX_PATTERN="juno?s?[-_]?.*\.(tgz|iso|img)"
JUNOS_TEMP_DIR="/var/tmp"
JUNOS_ALTERNATIVE_ROOT_PATH="/.mount"

process_storage_mount_points() {
    _possible_mount_points="$1"
    _storage_output="$2"
    
    # Initialize variables
    _target_filesystem=""
    _available_blocks=0
    _free_space=0
    JUNOS_BYTES_PER_BLOCK=1024

    #log_message "INFO" "_possible_mount_points: $_possible_mount_points"
    for mount_point in $_possible_mount_points; do
        #log_message "INFO" "mount_point: $mount_point"
        # Modified grep to be more precise about mount point matching
        line_match=$(echo "$_storage_output" | grep "[[:space:]]${mount_point}[[:space:]]*$")
        #log_message "INFO" "line_match: $line_match"
        if [ "$line_match" ]; then
            _target_filesystem=$(echo "$line_match" | awk '{print $1}')
            _available_blocks=$(echo "$line_match" | awk '{print $4}')
            _free_space=$(($_available_blocks * $JUNOS_BYTES_PER_BLOCK))
            log_message "INFO" "Target Filesystem: $_target_filesystem"
            log_message "INFO" "Available Blocks: $_available_blocks"
            log_message "INFO" "Free Space: $_free_space"
            break
        fi
    done

    # Return values through caller variables
    eval "$3='$_target_filesystem'"
    eval "$4='$_available_blocks'"
    eval "$5='$_free_space'"
}

# System health check function
check_system_health() {
    log_message "INFO" "Starting system health check"

    # Define commands
    file_list_cmd="file list detail $JUNOS_TEMP_DIR"
    storage_cmd="show system storage detail"
    
    # Get file list and storage information
    log_message "COMMAND" "Executing: $file_list_cmd"
    file_list_output=$(cli -c "$file_list_cmd")
    #log_message "Result" "file_list_output: $file_list_output"
    #log_message "COMMAND" "Executing: $storage_cmd"
    storage_output=$(cli -c "$storage_cmd")
    #log_message "Result" "storage_output: $storage_output"
    if [ $? -ne 0 ]; then
        log_message "WARNING" "Could not fetch list of files from dir on device"
        return 1
    fi

    # Process storage information
    # Get parent directories of JUNOS_TEMP_DIR
    current_dir="$JUNOS_TEMP_DIR"
    possible_mount_points="$JUNOS_TEMP_DIR /.mount/tmp"  # Add the actual mounted path
    while [ "$current_dir" != "/" ]; do
        current_dir=$(dirname "$current_dir")
        possible_mount_points="$possible_mount_points $current_dir"
        # Add alternative root path variants, but also tmp and hostvar
        possible_mount_points="$possible_mount_points $JUNOS_ALTERNATIVE_ROOT_PATH$current_dir /.mount/tmp /.mount/hostvar"
    done
    # Remove duplicates
    # log_message "Result" "possible_mount_points: $possible_mount_points"

    # Find target filesystem
    target_filesystem=""
    available_blocks=0
    free_space=0

    # Process storage output to find matching mount point
    process_storage_mount_points "$possible_mount_points" "$storage_output" target_filesystem available_blocks free_space

    # Extract and check free space
    log_message "INFO" "Target Filesystem: $target_filesystem"
    log_message "RESULT" "Available Space: $free_space"

    if [ -z "$target_filesystem" ]; then
        log_message "WARNING" "Failed to find target filesystem on device"
        free_space=0
    fi

    # Comprehensive space checking
    required_space=$(get_space_requirement "$MODEL")
    if [ -z "$required_space" ]; then
        log_message "WARNING" "Unknown model space requirements, using default 1GB"
        required_space=$AVG_SPACE_REQ
    fi
    log_message "INFO" "Space check - Required: ${required_space} bytes, Available: ${free_space} bytes"

    if [ -z "$free_space" ]; then
        handle_error "Could not determine free space"
    fi

    # Check for critical space issues
    if [ "${free_space}" -lt $MIN_SPACE_REQ ]; then
        handle_error "Critical: Low storage space: $free_space"
    fi

    if [ $free_space -lt $required_space ]; then
        handle_error "Insufficient space. Required: ${required_space} bytes, Available: ${free_space} bytes"
    fi

}


# ERROR HANDLING
handle_error() {
    local error_msg="$1"
    # Use parameter substitution for default value
    local error_code="${2:-1}"  # Default to 1 if not specified

    log_message "ERROR" "=========== ERROR DETAILS ==========="
    log_message "ERROR" "Message: $error_msg"
    # FUNCNAME is bash-specific, so we'll remove or modify this
    # log_message "ERROR" "Location: ${FUNCNAME[1]}"
    log_message "ERROR" "Command: $LAST_COMMAND"
    log_message "ERROR" "Exit Code: $error_code"

    # Attempt cleanup if needed
    if [ "$TEST_MODE" != "true" ]; then
        cleanup_on_error
    fi

    exit $error_code
}

cleanup_on_error() {
    log_message "NOTICE" "Performing cleanup..."

    # Rollback any config changes
    cli -c " configure exclusive; rollback 0; commit and-quit" >/dev/null 2>&1

    # Remove temporary files
    rm -f "$CONFIG_FILE" "$FIRMWARE_FILE" >/dev/null 2>&1

    log_message "NOTICE" "Cleanup completed"
}

cli_execute() {
    local cmd="$1"
    local result
    result=$(cli -c "$cmd" 2>&1)
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Command failed: $cmd"
        log_message "ERROR" "Output: $result"
        handle_error "CLI execution failed"
        exit 1
    fi
    echo "$result"
}


check_character() {
    local file="$1"
    local char="$2"
    while IFS= read -r line
    do
        # log_message "INFO" "$line"
        if grep -q "{" "$file"; then
            return 0   # True in shell
        fi
    done < "$file"
    return 1    # False in shell
}

download_configuration() {
    local retry_count=0
    local success=false

    while [ $retry_count -lt $MAX_RETRIES ] && [ "$success" = false ]; do
        log_message "INFO" "Downloading configuration (Attempt $((retry_count + 1)) of $MAX_RETRIES)"
        
        # Try to download configuration
        # log_message "COMMAND" "tftp -JG $REMOTE_SERVER:$CONFIG_FILE $CONFIG_PATH"
        tftp -JG $REMOTE_SERVER:$CONFIG_FILE $CONFIG_PATH
        if [ $? -eq 0 ]; then
            FULL_CONFIG_PATH="${CONFIG_PATH}/${CONFIG_FILE}"
            log_message "INFO" "Configuration download complete"
            log_message "INFO" "Verifying configuration..."
            if [ -f "$FULL_CONFIG_PATH" ]; then
                
                log_message "INFO" "Configuration verified. Download successful"
                # log_message "DEBUG" "$(cat $FULL_CONFIG_PATH)"
                success=true
                break
            else
                log_message "INFO" "Configuration verification failed"
                log_message "WARNING" "Configuration file not found at $FULL_CONFIG_PATH"
            fi
        else
            log_message "WARNING" "TFTP download failed"
        fi

        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            log_message "WARNING" "Download failed, retrying in 10 seconds..."
            sleep 10
        else
            log_message "ERROR" "Download failed after $MAX_RETRIES attempts"
            handle_error "Configuration download failed"    
            return 1
        fi
    done

    if [ "$success" = false ]; then
        handle_error "Failed to download configuration after $MAX_RETRIES attempts"
        return 1
    fi
    return 0
}

apply_configuration_with_retries() {
    local retry_count=0
    local success=false

    while [ $retry_count -lt $MAX_RETRIES ] && [ "$success" = false ]; do
        log_message "INFO" "Applying configuration (Attempt $((retry_count + 1)) of $MAX_RETRIES)"
        
        log_message "DEBUG" "Loading configuration and comparing with rollback"
        log_message "COMMAND" "configure exclusive; load override $FULL_CONFIG_PATH; show | compare"
        COMPARE_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH; show | compare")
        
        if [ $? -eq 0 ]; then
            log_message "INFO" "Configuration loaded, attempting commit"
            
            if check_character "$FULL_CONFIG_PATH" '{'; then
                log_message "INFO" "Configuration is in Junos curly brace format, applying command"
                COMMIT_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH; commit")
                # COMMIT_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH") FOR TESTING
            else
                log_message "INFO" "Configuration is in SET format, applying SET command"
                COMMIT_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH; commit")
                # COMMIT_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH") FOR TESTING
            fi
            
            log_message "DEBUG" "Commit output: $COMMIT_OUTPUT"
            
            if echo "$COMMIT_OUTPUT" | grep -qi "error\|failed\|unknown command"; then
            log_message "ERROR" "Configuration commit failed"
            success=false
            else
                log_message "INFO" "Configuration applied successfully"
                success=true
                break
            fi
        fi

        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            log_message "WARNING" "Configuration application failed, retrying in 30 seconds..."
            sleep 30
        else
            log_message "ERROR" "Configuration application failed after $MAX_RETRIES attempts"
            handle_error "Configuration application failed"
            return 1
        fi
    done

    if [ "$success" = false ]; then
        handle_error "Failed to apply configuration after $MAX_RETRIES attempts"
        return 1
    fi

    log_message "DEBUG" "Verifying configuration was applied"
    VERIFY_OUTPUT=$(cli -c "show configuration | display set")
    # log_message "DEBUG" "Current configuration: $VERIFY_OUTPUT"

    return 0
}


download_image() {
    local retry_count=0
    local start_time
    local local_path="/var/tmp/$TARGET_FIRMWARE_FILE"

    log_message "INFO" "Starting firmware download and installation process"

    # Check if firmware exists locally first
    log_message "INFO" "Checking for existing firmware file: $local_path"
    if [ -f "$local_path" ]; then
        log_message "INFO" "Found existing firmware file, verifying MD5"
        if verify_firmware_md5 "$local_path" "$TARGET_FIRMWARE_MD5"; then
            log_message "NOTICE" "Existing firmware file verified successfully"
            # Install the existing firmware
            log_message "INFO" "Installing existing firmware file"
            INSTALL_OUTPUT=$(cli -c "request system software add $local_path no-validate" 2>&1)
            INSTALL_STATUS=$?
            
            if [ $INSTALL_STATUS -eq 0 ] && ! echo "$INSTALL_OUTPUT" | grep -qi "ERROR"; then
                log_message "NOTICE" "Firmware installed successfully"
                if ! attempt_reboot; then
                    log_message "ERROR" "Reboot failed after successful installation"
                    return 1
                fi
                return 0
            fi
            log_message "WARNING" "Installation of existing file failed, will attempt download"
        else
            log_message "WARNING" "Existing firmware file MD5 verification failed, will attempt download"
        fi
    fi

    # If we get here, we need to download the firmware
    while [ $retry_count -lt $MAX_RETRIES ]; do
        retry_count=$((retry_count + 1))
        log_message "INFO" "Download attempt $retry_count of $MAX_RETRIES"

        # Download with curl using resume capability
        log_message "COMMAND" "curl -C - -o \"$local_path\" \"http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE\""
        if ! curl -C - -o "$local_path" "http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE"; then
            log_message "ERROR" "Curl download failed"
            if [ $retry_count -lt $MAX_RETRIES ]; then
                log_message "NOTICE" "Waiting $RETRY_DELAY seconds before next attempt"
                sleep $RETRY_DELAY
                continue
            else
                handle_error "All download attempts failed"
                return 1
            fi
        fi

        # Verify MD5 if needed
        if ! verify_firmware_md5 "$local_path" "$TARGET_FIRMWARE_MD5"; then
            log_message "ERROR" "MD5 verification failed, retrying download"
            continue
        fi

        # Install the downloaded firmware
        log_message "INFO" "Download successful, installing firmware"
        INSTALL_OUTPUT=$(cli -c "request system software add $local_path no-validate" 2>&1)
        INSTALL_STATUS=$?

        if [ $INSTALL_STATUS -eq 0 ] && ! echo "$INSTALL_OUTPUT" | grep -qi "ERROR"; then
            log_message "NOTICE" "Firmware installed successfully"
            
            # Attempt reboot with retries
            if ! attempt_reboot; then
                log_message "ERROR" "Reboot failed after successful installation"
                return 1
            fi
            return 0
        else
            log_message "ERROR" "Installation failed. Output: $INSTALL_OUTPUT"
            if [ $retry_count -lt $MAX_RETRIES ]; then
                log_message "NOTICE" "Waiting $RETRY_DELAY seconds before next attempt"
                sleep $RETRY_DELAY
                continue
            fi
        fi
    done

    handle_error "Exceeded maximum retry attempts"
    return 1
}



prepare_upgrade_command() {
    UPGRADE_CMD_FULL=""
    if [ -n "$FORCE_HOST" ]; then
        UPGRADE_CMD_FULL="$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE $FORCE_HOST"
    else
        if [ -n "$SKIP_VALIDATION" ]; then
            UPGRADE_CMD_FULL="$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE $SKIP_VALIDATION"
        else
            UPGRADE_CMD_FULL="$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE validate unlink"
        fi
    fi
    
    [ -n "$UPGRADE_CMD_FULL" ] || return 1
    return 0
}

attempt_reboot() {
    local reboot_retries=3
    local reboot_retry_count=0

    while [ $reboot_retry_count -lt $reboot_retries ]; do
        reboot_retry_count=$((reboot_retry_count + 1))
        log_message "NOTICE" "Initiating system reboot (attempt $reboot_retry_count)"
        
        REBOOT_OUTPUT=$(cli -c "request system reboot" 2>&1)
        REBOOT_STATUS=$?
        
        if [ $REBOOT_STATUS -eq 0 ] && ! echo "$REBOOT_OUTPUT" | grep -qi "ERROR"; then
            log_message "NOTICE" "Reboot command issued successfully"
            sleep $REBOOT_WAIT
            
            # If we're still running after sleep, something went wrong
            log_message "ERROR" "System failed to reboot after firmware installation"
            return 1
        fi
        
        if [ $reboot_retry_count -lt $reboot_retries ]; then
            log_message "WARNING" "Reboot attempt failed, retrying in 5 seconds..."
            sleep 5
        fi
    done

    return 1
}


main() {
    log_message "NOTICE" "Starting ZTP process"
    log_message "NOTICE" "Host: $HOSTNAME"
    log_message "INFO" "*** PRE-CHECKS ***"
    running_shell=$(ps -p $$ | tail -1 | awk '{print $4}')
    log_message "NOTICE" "Current shell: $running_shell"
    log_message "INFO" "*** PRE-CHECKS COMPLETE***"

    # Version check
    log_message "INFO" "*** COMMAND SET PHASE ***"
    log_message "INFO" "TARGET_FIRMWARE_FILE: $TARGET_FIRMWARE_FILE"
    log_message "INFO" "TARGET_VERSION: $TARGET_VERSION"
    check_version
    log_message "INFO" "*** COMMAND SET PHASE COMPLETE ***"

    # Firmware upgrade if needed
    log_message "INFO" "*** FIRMWARE COMPLIANCE PHASE ***"
    log_message "INFO" "Checking firmware version compliance..."
    log_message "INFO" "CURRENT_VERSION: $CURRENT_VERSION"
    log_message "INFO" "TARGET_VERSION: $TARGET_VERSION"
    
    
    if [ "$CURRENT_VERSION" != "$TARGET_VERSION" ]; then
        log_message "NOTICE" "Current firmware version not compliant"
        log_message "NOTICE" "Beginning firmware upgrade..."

        # Initial health check
        log_message "INFO" "*** CHECK SYSTEM HEALTH PHASE ***"
        check_system_health
        download_image
        log_message "INFO" "*** CHECK SYSTEM HEALTH PHASE COMPLETE ***"
        
        log_message "INFO" "*** FIRMWARE IMAGE ***" 

    fi

    log_message "NOTICE" "Firmware version is compliant"
    log_message "INFO" "*** FIRMWARE COMPLIANCE PHASE COMPLETE ***"
    

    log_message "INFO" "*** CONFIGURATION PHASE ***"
    # download and verify config
    if ! download_configuration; then
        exit 1
    fi
    log_message "INFO" "Verifying downloaded configuration"
    
    # apply config
    if ! apply_configuration_with_retries; then
        log_message "ERROR" "Configuration application phase failed"
        exit 1
    fi

    log_message "INFO" "Configuration application phase completed successfully"
    log_message "INFO" "*** CONFIGURATION PHASE COMPLETE ***"

    # Final verification
    log_message "INFO" "*** FINAL HEALTH CHECK PHASE ***"
    check_system_health
    log_message "INFO" "*** FINAL HEALTH CHECK PHASE COMPLETE ***"
    log_message "NOTICE" "ZTP process completed successfully"
}


# Execute main function

if [ -n "$TARGET_FIRMWARE_FILE" ]; then
    log_message "NOTICE" "Starting full ZTP process with firmware checks"
    main
else
    log_message "NOTICE" "Starting simple config-only ZTP process"
        log_message "INFO" "*** CONFIGURATION PHASE ***"
    # download and verify config
    if ! download_configuration; then
        exit 1
    fi
    log_message "INFO" "Verifying downloaded configuration"
    
    # apply config
    if ! apply_configuration_with_retries; then
        log_message "ERROR" "Configuration application phase failed"
        exit 1
    fi

    log_message "INFO" "Configuration application phase completed successfully"
    log_message "INFO" "*** CONFIGURATION PHASE COMPLETE ***"

    # Final verification
    log_message "NOTICE" "ZTP process completed successfully"
fi

