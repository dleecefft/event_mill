"""
Navigation Tools - Bucket/file listing and reading

Tools:
- list_buckets: List available GCS buckets
- list_logs: List files in a bucket/folder
- read_log_segment: Read chunks of a log file
- get_log_metadata: Get file metadata
"""

import logging


def register_navigation_tools(mcp, storage_client, get_bucket_func):
    """Register navigation tools with the MCP server."""
    
    # Store references for use in tool functions
    _storage_client = storage_client
    _get_bucket = get_bucket_func
    
    @mcp.tool()
    def list_buckets() -> str:
        """
        Lists all accessible GCS buckets. 
        Returns a single item list if GCS_LOG_BUCKET is set.
        """
        import os
        DEFAULT_BUCKET = os.getenv("GCS_LOG_BUCKET")
        
        if not _storage_client:
            result = "Error: GCS Client not initialized. Check credentials."
            logging.debug(f"list_buckets returning: {repr(result)}")
            return result
        
        if DEFAULT_BUCKET:
            result = f"Context restricted to single bucket: {DEFAULT_BUCKET}"
            logging.debug(f"list_buckets returning: {repr(result)}")
            return result

        try:
            buckets = [bucket.name for bucket in _storage_client.list_buckets()]
            if buckets:
                result = "\n".join(buckets)
            else:
                result = "No buckets found or access denied."
            logging.debug(f"list_buckets returning: {repr(result)}")
            return result
        except Exception as e:
            result = f"Error listing buckets: {str(e)}"
            logging.debug(f"list_buckets returning: {repr(result)}")
            return result

    @mcp.tool()
    def list_logs(bucket_name: str = "", prefix: str = "", max_results: int = 50) -> str:
        """
        List log files and subfolders in the configured GCS bucket. 
        Uses directory-style listing (non-recursive) for better navigation.
        
        Args:
            bucket_name: Optional if GCS_LOG_BUCKET env var is set.
            prefix: Folder path to list (e.g. 'folder/').
        """
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            
            # Ensure prefix ends with / if it's not empty, to treat it as a folder
            if prefix and not prefix.endswith('/'):
                prefix += '/'

            # Use delimiter='/' to emulate directory listing
            blobs_iterator = bucket.list_blobs(prefix=prefix, max_results=max_results, delimiter='/')
            
            results = []
            file_count = 0
            folder_count = 0
            
            # 1. Iterate over blobs to populate prefixes (folders)
            file_list = []
            for blob in blobs_iterator:
                name = blob.name
                if name == prefix:  # Skip the folder marker itself
                    continue
                file_list.append(name)
                file_count += 1
                
            # 2. Add Subfolders
            for subfolder in blobs_iterator.prefixes:
                results.append(f"📁 {subfolder}")
                folder_count += 1
                
            # 3. Add Files
            for file_path in file_list:
                results.append(f"📄 {file_path}")

            # Add Debug Summary Header
            debug_header = f"--- Debug: Found {file_count} files, {folder_count} folders (Prefix: '{prefix}') ---"
            results.insert(0, debug_header)

            if not file_list and not results:
                return f"--- Debug: Prefix='{prefix}' ---\n(No files or folders found)"
                
            return "\n".join(results)

        except Exception as e:
            return f"Error listing logs: {str(e)}"

    @mcp.tool()
    def read_log_segment(file_name: str, bucket_name: str = "", offset_lines: int = 0, line_limit: int = 100) -> str:
        """
        Reads a specific segment of a log file. 
        Use this to paginate through large log files.
        
        Args:
            file_name: Path to the file in the bucket
            bucket_name: Optional if GCS_LOG_BUCKET env var is set.
            offset_lines: Number of lines to skip (default 0)
            line_limit: Max lines to return (default 100)
        """
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            lines = []
            lines_read = 0
            
            with blob.open("r", encoding="utf-8", errors="replace") as f:
                # Skip to offset
                for _ in range(offset_lines):
                    if not f.readline():
                        return f"End of file reached at line {offset_lines}."
                
                # Read limit
                for _ in range(line_limit):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line.rstrip('\n'))
                    lines_read += 1
            
            if not lines:
                return f"End of file reached. No content at offset {offset_lines}."

            output = f"--- Showing lines {offset_lines} to {offset_lines + lines_read} ---\n"
            output += "\n".join(lines)
            
            if lines_read == line_limit:
                output += f"\n\n--- More lines may exist. Call with offset_lines={offset_lines + lines_read} to continue ---"
                
            return output

        except Exception as e:
            return f"Error reading log: {str(e)}"

    @mcp.tool()
    def get_log_metadata(file_name: str, bucket_name: str = "") -> str:
        """Returns size, updated time, and other metadata for a log file."""
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.get_blob(file_name)
            if not blob:
                return "File not found."
                
            return (
                f"File: {blob.name}\n"
                f"Size: {blob.size} bytes\n"
                f"Created: {blob.time_created}\n"
                f"Updated: {blob.updated}\n"
                f"Content Type: {blob.content_type}"
            )
        except Exception as e:
            return f"Error getting metadata: {str(e)}"
