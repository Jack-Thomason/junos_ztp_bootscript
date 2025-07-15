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
HOSTNAME="{hostname}"
REMOTE_SERVER="{tftp_server}" 
CONFIG_PATH="/var/tmp/"
FIRMWARE_PATH="/var/tmp/"

CONFIG_FILE="$HOSTNAME.cfg" 
LOG_FILE="/var/log/ztp-upgrade.log"
TARGET_FIRMWARE_FILE="{target_version}"
FIRMWARE_PATH=""

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
        "DEBUG")   LOG_ENTRY="DEBUG   | $TIMESTAMP | $MESSAGE" ;; # Detailed debug information
        "INFO")    LOG_ENTRY="INFO    | $TIMESTAMP | $MESSAGE" ;; # Normal execution messages
        "NOTICE")  LOG_ENTRY="NOTICE  | $TIMESTAMP | $MESSAGE" ;; # Important normal conditions
        "WARNING") LOG_ENTRY="WARNING | $TIMESTAMP | $MESSAGE" ;; # Warning conditions
        "ERROR")   LOG_ENTRY="ERROR   | $TIMESTAMP | $MESSAGE" ;; # Error conditions
        "COMMAND") LOG_ENTRY="COMMAND | $TIMESTAMP | $MESSAGE" ;; # CLI commands being executed
        "RESULT")  LOG_ENTRY="RESULT  | $TIMESTAMP | $MESSAGE" ;; # Command output/results
        *)         LOG_ENTRY="INFO    | $TIMESTAMP | $MESSAGE" ;; # Default to INFO
    esac

    # print to console
    echo "$LOG_ENTRY"

    # append to log file
    echo "$LOG_ENTRY" >> "$LOG_FILE" 
}


# FIRMWARE CHECKS
# Version comparison function
check_version() {
    log_message "INFO" "Starting version check"

    # Get model and version
    log_message "DEBUG" "Getting device model"
    log_message "COMMAND" "show version | grep Model: | trim 7"
    MODEL=$(cli_execute "show version | grep Model: | trim 7")
    log_message "RESULT" "Model: $MODEL"
    log_message "INFO" "Setting firmware file path"
    set_firmware_path $MODEL

    log_message "DEBUG" "Getting current version"
    log_message "COMMAND" "show version" | grep "Junos:" | grep -o "[0-9]\+\.[0-9]R[0-9]-S[0-9]"
    CURRENT_VERSION=$(cli_execute "show version | grep Junos:" | sed 's/.*Junos: //' | sed 's/[a-zA-Z].*//')

    log_message "RESULT" "Version: $CURRENT_VERSION"

    log_message "DEBUG" "Validating CURRENT_VERSION and TARGET_VERSION existence"
    # Validate version information
    if [ -z "$CURRENT_VERSION" ] || [ -z "$TARGET_VERSION" ]; then
        handle_error "Invalid version information"
    fi

    #log_message "DEBUG" "Validating TARGET_VERSION format"
    # May not be needed
    #if ! echo "$TARGET_VERSION" | grep -q "[0-9]\+\.[0-9]\+[A-Z][0-9]\+-[A-Z][0-9]\+[\.]*[0-9]*"; then
    #    handle_error "Invalid target version format: $TARGET_VERSION"
    #fi

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
    if [$FIRMWARE_PATH -z]; then
    log_message "INFO" "Firmware path unset...continue"
    fi
}

validate_version() {
    if [ -z "$CURRENT_VERSION" ] || [ -z "$TARGET_VERSION" ]; then
        handle_error "Invalid version information"
    fi

    # if ! echo "$TARGET_VERSION" | grep -q "^[0-9]\+\.[0-9]\+[A-Z][0-9]\+\.[0-9]\+$"; then
    #     handle_error "Invalid version format: $TARGET_VERSION"
    # fi
}


# Firmware verification function
verify_firmware() {
    if [ "$TEST_MODE" = true ]; then
        log_message "NOTICE" "Test Mode: Verifying firmware"
        log_message "INFO" "Would verify firmware: $FIRMWARE_FILE"
        return 0
    fi

    if [ ! -f $FIRMWARE_FILE ]; then
        handle_error "Firmware file not found"
    fi

    case "$MODEL" in
        *"qfx5110"*|*"qfx5120"*)
            log_message "NOTICE" "Skipping validation for $MODEL"
            return
            ;;
        *"ptx"*|*"jnp"*|*"mx304"*)
            log_message "COMMAND" "request vmhost software validate $FIRMWARE_FILE"
            cli -c "request vmhost software validate $FIRMWARE_FILE"
            ;;
        *"ex4600"*|*"srx4100"*|*"srx1500"*)
            log_message "COMMAND" "request system software validate $FIRMWARE_FILE"
            cli -c "request system software validate $FIRMWARE_FILE"
            ;;
        *)
            log_message "COMMAND" "request system software validate $FIRMWARE_FILE"
            cli -c "request system software validate $FIRMWARE_FILE"
            ;;
    esac

    if [ $? -ne 0 ]; then
        handle_error "Firmware validation failed"
    fi

    log_message "NOTICE" "Firmware verification passed"
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

    log_message "INFO" "_possible_mount_points: $_possible_mount_points"
    for mount_point in $_possible_mount_points; do
        log_message "INFO" "mount_point: $mount_point"
        # Modified grep to be more precise about mount point matching
        line_match=$(echo "$_storage_output" | grep "[[:space:]]${mount_point}[[:space:]]*$")
        log_message "INFO" "line_match: $line_match"
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
    log_message "Result" "file_list_output: $file_list_output"
    log_message "COMMAND" "Executing: $storage_cmd"
    storage_output=$(cli -c "$storage_cmd")
    log_message "Result" "storage_output: $storage_output"
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
    log_message "Result" "possible_mount_points: $possible_mount_points"

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

# Test destructive commands safely
test_destructive_commands() {
    log_message "NOTICE" "Testing destructive commands in safe mode"
    local failed=0

    # Test configuration commands
    log_message "INFO" "Testing configuration commands"

    # Test configure exclusive (dry run)
    log_message "COMMAND" "configure exclusive"
    if cli -c "configure exclusive" >/dev/null 2>&1; then
        log_message "RESULT" "✓ Can enter exclusive configuration mode"
        cli -c "exit" >/dev/null 2>&1
    else
        log_message "ERROR" "✗ Cannot enter exclusive configuration mode"
        failed=$((failed + 1))
    fi

    # Test commit syntax
    log_message "COMMAND" "commit check"
    if cli -c "configure exclusive; commit check; exit" >/dev/null 2>&1; then
        log_message "RESULT" "✓ Commit check command available"
    else
        log_message "ERROR" "✗ Commit check failed"
        failed=$((failed + 1))
    fi

    # Test firmware commands based on model
    log_message "INFO" "Testing firmware commands"
    case "$MODEL" in
        *"srx4100"*|*"srx1500"*)
            cmd="request system software validate ?"
            ;;
        *"ptx"*|*"jnp"*|*"mx304"*)
            cmd="request vmhost software validate ?"
            ;;
        *)
            cmd="request system software validate ?"
            ;;
    esac

    log_message "COMMAND" "$cmd"
    if cli -c "$cmd" >/dev/null 2>&1; then
        log_message "RESULT" "✓ Firmware validation command available"
    else
        log_message "ERROR" "✗ Firmware validation command not available"
        failed=$((failed + 1))
    fi

    # Test file operations safely
    log_message "INFO" "Testing file operations"

    # Test file command syntax
    log_message "COMMAND" "file ?"
    if cli -c "file ?" >/dev/null 2>&1; then
        log_message "RESULT" "✓ File operations available"
    else
        log_message "ERROR" "✗ File operations not available"
        failed=$((failed + 1))
    fi

    return $failed
}


# MAIN EXECUTION FLOW
main() {
    log_message "NOTICE" "Starting ZTP process"
    log_message "NOTICE" "Host: $HOSTNAME"
    log_message "INFO" "*** PRE-CHECKS ***"
    running_shell=$(ps -p $$)
    log_message "NOTICE" "Current shell: $running_shell"
    log_message "INFO" "*** PRE-CHECKS COMPLETE***"
    log_message "INFO" "*****************************************"
    log_message "INFO" "*****************************************"
    
    log_message "INFO" "TARGET_FIRMWARE_FILE: $TARGET_FIRMWARE_FILE"
    log_message "INFO" "TARGET_VERSION: $TARGET_VERSION"
    
    # Version check
    log_message "INFO" "*** COMMAND SET PHASE ***"
    check_version
    log_message "INFO" "*** COMMAND SET PHASE COMPLETE ***"
    log_message "INFO" "*****************************************"
    log_message "INFO" "*****************************************"

    # Firmware upgrade if needed
    log_message "INFO" "*** FIRMWARE PHASE ***"
    log_message "INFO" "CURRENT_VERSION: $CURRENT_VERSION"
    log_message "INFO" "TARGET_VERSION: $TARGET_VERSION"
    
    if [ "$CURRENT_VERSION" != "$TARGET_VERSION" ]; then
        log_message "NOTICE" "Firmware upgrade needed"

        # Initial health check
        log_message "INFO" "*** CHECK SYSTEM HEALTH PHASE ***"
        check_system_health
        log_message "INFO" "*** CHECK SYSTEM HEALTH PHASE COMPLETE ***"
        log_message "INFO" "*****************************************"
        log_message "INFO" "*****************************************"
        log_message "INFO" "Starting firmware download: $TARGET_FIRMWARE_FILE"
        log_message "NOTICE" "Starting firmware installation"
        
        if [ -n "$FORCE_HOST" ]; then
            log_message "COMMAND" "$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE $FORCE_HOST"
            INSTALL_OUTPUT=$(cli -c "$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE $FORCE_HOST" 2>&1)
        else
            if [ -n "$SKIP_VALIDATION" ]; then
                log_message "COMMAND" "$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE $SKIP_VALIDATION"
                INSTALL_OUTPUT=$(cli -c "$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE $SKIP_VALIDATION" 2>&1)
            else
                log_message "COMMAND" "$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE validate unlink"
                INSTALL_OUTPUT=$(cli -c "$UPGRADE_CMD http://$REMOTE_SERVER/$FIRMWARE_PATH/$TARGET_FIRMWARE_FILE validate unlink" 2>&1)
            fi
        fi
        INSTALL_STATUS=$?
        if echo "$INSTALL_OUTPUT" | grep -qi "ERROR\|Operation timed out\|Cannot fetch file"; then
            log_message "ERROR" "Firmware installation failed with output: $INSTALL_OUTPUT"
            handle_error "Firmware installation failed"
            exit 1
        fi

        if [ $INSTALL_STATUS -ne 0 ]; then
            log_message "ERROR" "Firmware installation failed with status: $INSTALL_STATUS"
            handle_error "Firmware installation failed"
            exit 1
        fi

        if [ $INSTALL_STATUS -eq 0 ]; then
            log_message "NOTICE" "Firmware installed successfully, reapplying auto-image-upgrade, then rebooting"
            log_message "COMMAND" "configure exclusive; set chassis auto-image-upgrade; commit; exit"
            REAPPLY_AUTO_IMAGE_UPGRADE=$(cli -c "configure exclusive; set chassis auto-image-upgrade; commit; exit")
            log_message "DEBUG" "REAPPLY_AUTO_IMAGE_UPGRADE: $REAPPLY_AUTO_IMAGE_UPGRADE"
            cli -c "request system reboot"
            exit 0
        fi
    fi
    
    log_message "INFO" "*** FIRMWARE PHASE COMPLETE ***"
    log_message "INFO" "*****************************************"
    log_message "INFO" "*****************************************"

    # Configuration application
    log_message "INFO" "*** CONFIGURATION PHASE ***"

    log_message "INFO" "Downloading configuration"
    pwd_response=`pwd`
    log_message "INFO" "pwd_response: $pwd_response"
    tftp -JG $REMOTE_SERVER:$CONFIG_FILE $CONFIG_PATH
    if [ $? -ne 0 ]; then
        handle_error "Configuration download failed"
    fi
    
    FULL_CONFIG_PATH="${CONFIG_PATH}/${CONFIG_FILE}"
    if [ ! -f "$FULL_CONFIG_PATH" ]; then
        handle_error "Configuration file not found at $FULL_CONFIG_PATH"
        exit 1
    fi

    verify_config
    log_message "DEBUG" "Configuration file content:"
    log_message "DEBUG" "$(cat $FULL_CONFIG_PATH)"
    log_message "INFO" "Config: $(cli -c "file show $FULL_CONFIG_PATH")"
    log_message "DEBUG" "Loading configuration and comparing with rollback"
    log_message "COMMAND" "configure exclusive; load override $FULL_CONFIG_PATH; show | compare"
    COMPARE_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH; show | compare")
    if [ $? -eq 0 ]; then
        log_message "INFO" "Configuration loaded, attempting commit"
        COMMIT_OUTPUT=$(cli -c "configure exclusive; load override $FULL_CONFIG_PATH; commit")
        COMMIT_STATUS=$?
        log_message "DEBUG" "Commit output: $COMMIT_OUTPUT"
        log_message "DEBUG" "Commit status: $COMMIT_STATUS"
        
        if [ $COMMIT_STATUS -ne 0 ]; then
            log_message "ERROR" "Failed to commit configuration"
            handle_error "Configuration commit failed"
            exit 1
        fi
    else
        log_message "ERROR" "Failed to load configuration"
        handle_error "Configuration load failed"
        exit 1
    fi

    log_message "DEBUG" "Verifying configuration was applied"
    VERIFY_OUTPUT=$(cli -c "show configuration | display set")
    log_message "DEBUG" "Current configuration: $VERIFY_OUTPUT"

    log_message "INFO" "*** CONFIGURATION PHASE COMPLETE ***"
    log_message "INFO" "*****************************************"
    log_message "INFO" "*****************************************"

    # Final verification
    log_message "INFO" "*** FINAL HEALTH CHECK PHASE ***"
    check_system_health
    log_message "INFO" "*** FINAL HEALTH CHECK PHASE COMPLETE ***"
    log_message "INFO" "*****************************************"
    log_message "INFO" "*****************************************"

    log_message "NOTICE" "ZTP process completed successfully"
}


# Execute main function
main