import typing
import urllib.parse # For URL encoding the search string

from mcp.server.fastmcp import Context

# Assuming these imports exist based on your example
from .. import utils # Or adjust path as needed
from ..server import server, vt_client

# (get_asm_issue_details function remains the same as in the previous version)
@server.tool()
async def get_asm_issue_details(id: str, ctx: Context) -> typing.Dict[str, typing.Any]:
  """
  Retrieves the detailed information for a specific Attack Surface Management (ASM) issue
  identified by its unique ID from Google Threat Intelligence (VirusTotal).

  ASM issues represent potential risks, misconfigurations, or vulnerabilities
  detected on the assets belonging to your monitored attack surface.

  Args:
    id (required): The unique identifier of the ASM issue. This is typically a
                   long alphanumeric string obtained from search results or other tools.
                   Example format: 'asm_issue_5a7b....c9d0'.

  Returns:
    A dictionary containing the detailed attributes and data for the requested ASM issue.
    For standard VT API v3, this is often {'data': { ... issue attributes ... }}.
    If the underlying client modifies this structure, the exact output may vary.
  """
  api_path = f"/asm/issues/{id}"
  try:
      response = await vt_client(ctx).get_async(api_path)
      data = await response.json_async()
      return data
  except Exception as e:
      print(f"Error fetching ASM issue details for ID {id}: {e}")
      return {"error": f"Failed to fetch ASM issue details for ID {id}. Reason: {str(e)}"}


@server.tool()
async def search_asm_issues(
    query: str, ctx: Context, limit: int = 10, cursor: typing.Optional[str] = None
) -> typing.Dict[str, typing.Any]:
  """
  Searches for Attack Surface Management (ASM) issues in Google Threat Intelligence
  (VirusTotal) based on a provided search query string.

  To replicate a direct API call like:
  `GET /asm/search/issues/collection%3A%22Acme%20-%20External%20discovery%20%26%20assessment%22?page_size=100`
  You would call this function with:
  `query='collection:\"Acme - External discovery & assessment\"'`
  `limit=100`

  Valid search keywords include: collection:name, name:string, uid:12345, tag:tag_name,
  last_seen_after:YYYY-MM-DD, last_seen_before:YYYY-MM-DD, first_seen_after:YYYY-MM-DD,
  entity_uid:12345, entity_type:string, entity_name:string, scoped:true|false,
  severity:1-5, severity_lte:1-5, severity_gte:1-5, status_new:open|closed,
  status_detailed:string. If no search keyword (operator) is used, the "name" field is searched.
  If no query string is entered, all issues for the project will be returned by the API.

  Args:
    query (required): The search string used to find ASM issues.
                      Example: 'collection:\"Your Collection Name\" severity_gte:4'.
                      The function will URL-encode this query.
    limit (optional): The maximum number of issues to return. Maps to API's 'page_size'.
                      Defaults to 10. Max is 1000.
    cursor (optional): Pagination cursor from a previous result's 'meta.next_page_token'.
                       Maps to API's 'page_token'.

  Returns:
    A dictionary representing the API's JSON response. For standard VT API v3,
    this is typically:
    {
      "data": [ { ... issue summary ... }, ... ],
      "meta": { "total_hits": X, "page_size": Y, "next_page_token": "...", ... },
      "links": { "self": "...", "next": "..." }
    }
    The exact structure of "meta" can vary. The uploaded 'asm_search.json' has a
    different top-level structure with a "result" key; this function returns what
    the vt_client provides, which is assumed to be the direct API response.
  """
  # URL-encode the query string part that goes into the path
  encoded_query_path_segment = urllib.parse.quote_plus(query)
  api_path = f"/asm/search/issues/{encoded_query_path_segment}"

  params = {"page_size": limit}
  if cursor:
      params["page_token"] = cursor

  try:
      response = await vt_client(ctx).get_async(api_path, params=params)
      # Ensure the response was successful before trying to parse JSON
      # response.raise_for_status() # Depending on how vt_client handles errors

      data = await response.json_async()
      return data
  except Exception as e:
      print(f"Error searching ASM issues with query '{query}': {e}")
      return {"error": f"Failed to search ASM issues with query '{query}'. Reason: {str(e)}"}
