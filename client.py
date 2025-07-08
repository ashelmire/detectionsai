#!/usr/bin/env python3

import requests
import argparse
import logging
import yaml
from datetime import datetime, timedelta
from typing import Any, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class DetectionsAI:
    def __init__(self, token):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {self.token}"
        }

    def get_detections(self, rule_type: str = "SIGMA", interval: int = 1, library="my-rules") -> Dict[str, Any]:
        """
        Get detections from the Detections.ai API.

        Note: detections.ai API uses a paginated response, so this method will retrieve all pages of results.
        Note2: the API only returns 10,000 results. 
        Args:
            rule_type (str): The type of rule to retrieve. Default is "SIGMA".
            interval (int): The time interval in days to filter rules. Default is 1 day.
        Returns:
            List[Tuple[str, str]]: A list of tuples containing the rule title and content.
        """
        rules = []
        modified_after = (datetime.utcnow() - timedelta(days=interval)).isoformat() + "Z"  # ISO 8601 format with Zulu time
        logger.debug(f"Fetching rules of type {rule_type} modified after {modified_after}")
        params = { 
            "query_text": "",
            "filters": {
                "rule_types": [rule_type],
                "metadata_modified_after": modified_after,
            },
            "options": {
                "page": 1,
                "size": 100,
                "sort_by": "metadata_modified",
                "sort_order": "desc"
                }
            }
        if library == "my-rules":
            url = "https://rule-manager.detections.ai/api/v1/rules/my-rules/search"
        else:
            url = "https://rule-manager.detections.ai/api/v1/rules/browse-detections"

        try:
            page = 1
            total_pages = 1
            while page <= total_pages:
                params["options"]["page"] = page
                resp = requests.post(
                    url,
                    headers=self.headers,
                    json=params
                )
                resp.raise_for_status()
                
                total_pages = resp.json().get("meta", {}).get("total_pages", 1)
                logger.debug(f"Page {page}/{total_pages} - Total Results: {resp.json().get('meta', {}).get('total', 0)}")
                page += 1
                for r in resp.json().get("data", []):
                    rule = r["title"]["value"], r["content"]
                    rules.append(rule)

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get detections: {resp.status_code}")
            return []
        logger.info(f"Processed Page {total_pages} - Total Results: {len(rules)} / {resp.json().get('meta', {}).get('total', 0)}")
        return rules

    def get_detection_by_id(self, detection_id: str) -> Dict[str, Any]:
        resp = requests.get(
            f"https://detections.ai/api/v1/rules/{detection_id}",
            headers=self.headers
        )
        if resp.status_code == 200:
            # return title to make it the same as the other methods
            return (resp.json()['title'],resp.json()['content'])
        else:
            print(f"Failed to get detection by ID: {resp.status_code} - {resp.text}")
            return {}

    def add_personal_intel(self, intel_url):
        """
        """
        resp = requests.post(
            f"https://detections.ai/api/v1/inspiration/urls",
            headers=self.headers,
            json={"name": intel_url, "tags": ["personal"], "url": intel_url }
        )
        if resp.status_code == 200:
            print("Personal intel added successfully.")
        else:
            print(f"Failed to add personal intel: {resp.status_code} - {resp.text}")


    def new_rule_with_ai(self, inspiration_hash: str, rule_type: str = "SIGMA") -> str:
        """
        Generate a new rule using AI based on an inspiration hash.
        Args:
            inspiration_hash (str): The hash of the inspiration to use for rule generation.
            rule_type (str): The type of rule to generate. Default is "SIGMA".
        Returns:
            str: The generated rule content.
        Raises:
            requests.exceptions.RequestException: If the request to the API fails.
        """
        '''
        try:
            resp = requests.post(
                f"https://cti-parser.detections.ai/api/v1/sessions",
                headers=self.headers,
                params = {"language": rule_type, "inspiration_ids": [inspiration_hash]},
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create AI session: {e}")
            return ""
        logger.info(resp.json().keys())
        
        {
            "session_id": "GUID",
            "session_title": "New Session",
            "language": "sigma",
            "language_locked": false,
            "title_generated": false,
            "created_at": "2025-07-08T01:36:43.742Z",
            "last_updated_at": "2025-07-08T01:36:43.742Z",
            "inspiration_ids": []
        }
        '''
        # TODO: Complete
        return "This feature is not yet implemented."

def output_rules(rules, output_dir, rule_type):
    """
    Write the rules to files in the specified output directory.
    
    Args:
        rules (List[Tuple[str, str]]): A list of tuples containing the rule title and content.
        output_dir (str): The directory to save the output files.
        rule_type (str): The type of rule to retrieve.
    """
    for title, content in rules:
        if output_dir is None:  # If no output directory is specified, print the rules
            print(f"Rule {title}:\n{content}\n\n")
            continue
        filename = f"{output_dir}/{title}.{rule_type.lower()}"
        with open(filename, "w") as f:
            f.write(content)
            logger.info(f"Rule {title} written to {filename}")
        
        
    logger.info(f"Finished outputting rules")

def main(args=None):
    token = args.token

    DetectionsAIClient = DetectionsAI(token)

    if args.action == 'my-rules':
        logger.info("Fetching my rules from Detections.ai")
        rules = DetectionsAIClient.get_detections(args.rule_type, interval=args.day_interval, library="my-rules")
        output_rules(rules, args.output, args.rule_type)
    elif args.action == 'get-rule':
        if not args.rule_id:
            logger.error("Rule ID is required for 'get-rule' action.")
            return
        logger.info(f"Fetching rule with ID {args.rule_id}")
        rule = DetectionsAIClient.get_detection_by_id(args.rule_id)
        if rule:
            output_rules([rule], args.output, args.rule_type)
        else:
            logger.error(f"Failed to retrieve rule with ID {args.rule_id}")
    elif args.action == 'get-rules':
        logger.info("Fetching all rules from Detections.ai")
        rules = DetectionsAIClient.get_detections(args.rule_type, interval=args.day_interval, library="browse")
        output_rules(rules, args.output, args.rule_type)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detections.ai cli script.")
    parser.add_argument("--token", help="The bearer token for authentication.")
    parser.add_argument("--action", default='my-rules', choices=['my-rules', 'get-rule', 'get-rules', 'new-rule-with-ai'], help="The action to take ['my-rules', 'get-rule', 'new-rule-with-ai'].")
    parser.add_argument("--output", default=None, help="The directory to save output files.")
    parser.add_argument("--rule-type", default="SIGMA", choices=["SIGMA", "SPL", "KQL","YARA", "S1QL"], help="The type of rule to retrieve.")    
    parser.add_argument("--rule-id", help="The rule guid to retrieve.")    
    parser.add_argument("--day-interval", type=int, default=1, help="The number of days within which to pull recently modified rules.")    
    args = parser.parse_args()

    main(args)
