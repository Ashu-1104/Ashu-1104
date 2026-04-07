<?php
/**
 * CSF File Operations Functions
 * Handles safe file reading, writing, and management
 * All operations include proper locking and atomic writes
 */

/**
 * Safe read file with locking
 * 
 * @param string $file_path Path to file
 * @return string|bool File contents or false on error
 */
function csf_read_file($file_path) {
    if (empty($file_path) || !is_string($file_path)) {
        csf_log("ERROR: Invalid file path provided", "error");
        return false;
    }

    if (!file_exists($file_path)) {
        csf_log("ERROR: File not found: $file_path", "error");
        return false;
    }

    if (!is_readable($file_path)) {
        csf_log("ERROR: File not readable: $file_path", "error");
        return false;
    }

    $fp = @fopen($file_path, 'r');
    if ($fp === false) {
        csf_log("ERROR: Failed to open file: $file_path", "error");
        return false;
    }

    if (!flock($fp, LOCK_SH)) {
        csf_log("ERROR: Failed to acquire read lock on file: $file_path", "error");
        fclose($fp);
        return false;
    }

    $contents = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return $contents !== false ? $contents : false;
}

/**
 * Read file as array of lines
 * 
 * @param string $file_path Path to file
 * @param int $flags File reading flags (FILE_IGNORE_NEW_LINES, FILE_SKIP_EMPTY_LINES)
 * @return array|bool Array of lines or false on error
 */
function csf_read_file_lines($file_path, $flags = FILE_IGNORE_NEW_LINES) {
    if (empty($file_path) || !is_string($file_path)) {
        csf_log("ERROR: Invalid file path provided", "error");
        return false;
    }

    if (!file_exists($file_path)) {
        return array(); // Return empty array if file doesn't exist
    }

    if (!is_readable($file_path)) {
        csf_log("ERROR: File not readable: $file_path", "error");
        return false;
    }

    $lines = @file($file_path, $flags);

    if ($lines === false) {
        csf_log("ERROR: Failed to read file: $file_path", "error");
        return false;
    }

    return $lines;
}

/**
 * Safe write file with atomic operation
 * 
 * @param string $file_path Path to file
 * @param string $content Content to write
 * @param int $mode File permission mode (default 0644)
 * @return bool True on success
 */
function csf_write_file($file_path, $content, $mode = 0644) {
    if (empty($file_path) || !is_string($file_path)) {
        csf_log("ERROR: Invalid file path provided", "error");
        return false;
    }

    if (!is_string($content)) {
        csf_log("ERROR: Content must be a string", "error");
        return false;
    }

    // Create directory if it doesn't exist
    $dir = dirname($file_path);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true)) {
            csf_log("ERROR: Failed to create directory: $dir", "error");
            return false;
        }
    }

    // Use temporary file for atomic write
    $temp_file = $file_path . '.tmp.' . uniqid();
    
    $fp = @fopen($temp_file, 'w');
    if ($fp === false) {
        csf_log("ERROR: Failed to open temp file for writing: $temp_file", "error");
        return false;
    }

    if (!flock($fp, LOCK_EX)) {
        csf_log("ERROR: Failed to acquire lock on temp file: $temp_file", "error");
        fclose($fp);
        @unlink($temp_file);
        return false;
    }

    $written = fwrite($fp, $content);
    flock($fp, LOCK_UN);
    fclose($fp);

    if ($written === false) {
        csf_log("ERROR: Failed to write to temp file: $temp_file", "error");
        @unlink($temp_file);
        return false;
    }

    // Set proper permissions before renaming
    @chmod($temp_file, $mode);

    // Atomic rename
    if (!@rename($temp_file, $file_path)) {
        csf_log("ERROR: Failed to move temp file to destination: $file_path", "error");
        @unlink($temp_file);
        return false;
    }

    return true;
}

/**
 * Append to file with locking
 * 
 * @param string $file_path Path to file
 * @param string $content Content to append
 * @return bool True on success
 */
function csf_append_file($file_path, $content) {
    if (empty($file_path) || !is_string($file_path)) {
        csf_log("ERROR: Invalid file path provided", "error");
        return false;
    }

    if (!is_string($content)) {
        csf_log("ERROR: Content must be a string", "error");
        return false;
    }

    // Create directory if it doesn't exist
    $dir = dirname($file_path);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true)) {
            csf_log("ERROR: Failed to create directory: $dir", "error");
            return false;
        }
    }

    $fp = @fopen($file_path, 'a');
    if ($fp === false) {
        csf_log("ERROR: Failed to open file for appending: $file_path", "error");
        return false;
    }

    if (!flock($fp, LOCK_EX)) {
        csf_log("ERROR: Failed to acquire lock on file: $file_path", "error");
        fclose($fp);
        return false;
    }

    $written = fwrite($fp, $content);
    flock($fp, LOCK_UN);
    fclose($fp);

    return $written !== false;
}

/**
 * Delete file safely
 * 
 * @param string $file_path Path to file
 * @return bool True on success
 */
function csf_delete_file($file_path) {
    if (empty($file_path) || !is_string($file_path)) {
        csf_log("ERROR: Invalid file path provided", "error");
        return false;
    }

    if (!file_exists($file_path)) {
        return true; // Consider non-existent file as successfully deleted
    }

    if (!is_writable(dirname($file_path))) {
        csf_log("ERROR: Directory not writable: " . dirname($file_path), "error");
        return false;
    }

    if (!@unlink($file_path)) {
        csf_log("ERROR: Failed to delete file: $file_path", "error");
        return false;
    }

    return true;
}

/**
 * Create directory with proper permissions
 * 
 * @param string $dir_path Path to directory
 * @param int $mode Directory permission mode (default 0755)
 * @return bool True on success
 */
function csf_create_directory($dir_path, $mode = 0755) {
    if (empty($dir_path) || !is_string($dir_path)) {
        csf_log("ERROR: Invalid directory path provided", "error");
        return false;
    }

    if (is_dir($dir_path)) {
        return true; // Already exists
    }

    if (!@mkdir($dir_path, $mode, true)) {
        csf_log("ERROR: Failed to create directory: $dir_path", "error");
        return false;
    }

    return true;
}

/**
 * Check if file or directory has write permissions
 * 
 * @param string $path Path to file or directory
 * @return bool True if writable
 */
function csf_is_writable($path) {
    if (empty($path)) {
        return false;
    }

    if (file_exists($path)) {
        return is_writable($path);
    }

    // Check parent directory
    $parent = dirname($path);
    return is_dir($parent) && is_writable($parent);
}

/**
 * List files in directory
 * 
 * @param string $dir_path Path to directory
 * @param string $pattern Optional glob pattern filter
 * @return array|bool Array of file paths or false on error
 */
function csf_list_files($dir_path, $pattern = '') {
    if (empty($dir_path) || !is_string($dir_path)) {
        csf_log("ERROR: Invalid directory path provided", "error");
        return false;
    }

    if (!is_dir($dir_path)) {
        csf_log("ERROR: Directory not found: $dir_path", "error");
        return false;
    }

    if (!is_readable($dir_path)) {
        csf_log("ERROR: Directory not readable: $dir_path", "error");
        return false;
    }

    if (!empty($pattern)) {
        $files = @glob($dir_path . '/' . $pattern);
    } else {
        $files = @scandir($dir_path);
        if ($files !== false) {
            // Remove . and ..
            $files = array_diff($files, array('.', '..'));
            // Prepend directory path
            $files = array_map(function($file) use ($dir_path) {
                return $dir_path . '/' . $file;
            }, $files);
        }
    }

    return $files !== false ? $files : false;
}

/**
 * Get file size in bytes
 * 
 * @param string $file_path Path to file
 * @return int|bool File size or false
 */
function csf_get_file_size($file_path) {
    if (empty($file_path) || !file_exists($file_path)) {
        return false;
    }

    return @filesize($file_path);
}

/**
 * Get file modification time
 * 
 * @param string $file_path Path to file
 * @return int|bool Modification time (Unix timestamp) or false
 */
function csf_get_file_mtime($file_path) {
    if (empty($file_path) || !file_exists($file_path)) {
        return false;
    }

    return @filemtime($file_path);
}

/**
 * Get file creation time
 * 
 * @param string $file_path Path to file
 * @return int|bool Creation time (Unix timestamp) or false
 */
function csf_get_file_ctime($file_path) {
    if (empty($file_path) || !file_exists($file_path)) {
        return false;
    }

    return @filectime($file_path);
}

/**
 * Copy file
 * 
 * @param string $source Source file path
 * @param string $destination Destination file path
 * @return bool True on success
 */
function csf_copy_file($source, $destination) {
    if (empty($source) || empty($destination)) {
        csf_log("ERROR: Invalid source or destination path", "error");
        return false;
    }

    if (!file_exists($source)) {
        csf_log("ERROR: Source file not found: $source", "error");
        return false;
    }

    if (!is_readable($source)) {
        csf_log("ERROR: Source file not readable: $source", "error");
        return false;
    }

    // Create destination directory if needed
    $dest_dir = dirname($destination);
    if (!is_dir($dest_dir)) {
        if (!csf_create_directory($dest_dir)) {
            return false;
        }
    }

    if (!@copy($source, $destination)) {
        csf_log("ERROR: Failed to copy file from $source to $destination", "error");
        return false;
    }

    // Copy permissions
    $perms = @fileperms($source);
    if ($perms !== false) {
        @chmod($destination, $perms);
    }

    return true;
}

/**
 * Check if path is safe (no directory traversal)
 * 
 * @param string $base_path Base directory path
 * @param string $requested_path Requested file path
 * @return bool True if path is safe
 */
function csf_is_safe_path($base_path, $requested_path) {
    if (empty($base_path) || empty($requested_path)) {
        return false;
    }

    $base_path = realpath($base_path);
    $requested_path = realpath($requested_path);

    if ($base_path === false || $requested_path === false) {
        return false;
    }

    // Check if requested path is within base path
    return strpos($requested_path, $base_path) === 0;
}

?>
