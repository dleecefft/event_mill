"""
Search Tools - Log searching functionality

Tools:
- search_log: Search for text in log files
"""

import logging


def register_search_tools(mcp, storage_client, get_bucket_func):
    """Register search tools with the MCP server."""
    
    _storage_client = storage_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def search_log(file_name: str, query: str, bucket_name: str = "", max_results: int = 50) -> str:
        """
        Searches a log file for lines containing a specific text query (case-insensitive).
        Returns matching lines with their line numbers.
        
        Args:
            file_name: Path to the file in the bucket
            query: String to search for
            bucket_name: Optional bucket override
            max_results: Max number of matches to return (default 50)
        """
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            matches = []
            match_count = 0
            line_number = 0
            
            with blob.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line_number += 1
                    if query.lower() in line.lower():
                        matches.append(f"{line_number}: {line.rstrip()}")
                        match_count += 1
                        if match_count >= max_results:
                            break
            
            if not matches:
                return f"No matches found for '{query}' in {file_name}."
                
            output = f"--- Found {match_count} matches for '{query}' (limit: {max_results}) ---\n"
            output += "\n".join(matches)
            
            if match_count >= max_results:
                output += "\n\n--- Search limit reached. Try a more specific query or different file. ---"
                
            return output

        except Exception as e:
            return f"Error searching log: {str(e)}"
